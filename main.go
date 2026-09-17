package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret []byte

// Thread-safe in-memory database maps
var (
	appDatabase   = sync.Map{}
	deviceStore   = sync.Map{}
	hostRegistry  = sync.Map{}
	userDatabase  = sync.Map{} // Username -> Account
	activeSession = sync.Map{} // Token -> Username
	apiTokenStore = sync.Map{} // TokenString -> APITokenRecord
)

type OAuthApp struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AppName      string   `json:"app_name"`
	RedirectUris []string `json:"redirect_uris"`
}

type DeviceCodeSession struct {
	DeviceCode string    `json:"device_code"`
	UserCode   string    `json:"user_code"`
	ClientID   string    `json:"client_id"`
	Scope      string    `json:"scope"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Account struct {
	Username string    `json:"username"`
	Password string    `json:"password"` // In production, use bcrypt hashes
	Prompt   string    `json:"prompt"`
	Created  time.Time `json:"created_at"`
}

type APITokenRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

type Country struct {
	Name string `json:"name"`
	Code string `json:"code"`
	Flag string `json:"flag"`
	Ping int    `json:"ping_ms"`
}

var vpnCountries = []Country{
	{"United States", "US", "🇺🇸", 21},
	{"United Kingdom", "UK", "🇬🇧", 40},
	{"Germany", "DE", "🇩🇪", 34},
	{"Japan", "JP", "🇯🇵", 108},
	{"Canada", "CA", "🇨🇦", 28},
	{"Australia", "AU", "🇦🇺", 142},
	{"Switzerland", "CH", "🇨🇭", 36},
	{"Singapore", "SG", "🇸🇬", 85},
	{"Netherlands", "NL", "🇳🇱", 31},
	{"France", "FR", "🇫🇷", 39},
}

var vpnState = struct {
	sync.Mutex
	Connected   bool   `json:"connected"`
	Country     string `json:"country"`
	IP          string `json:"ip"` // Format: 10.x.x.x
	Speed       string `json:"speed"`
	ConnectedAt string `json:"connected_at,omitempty"`
}{Connected: false, Country: "None", IP: "127.0.0.1", Speed: "0 ms"}

const htmlContent = `<!DOCTYPE html>
<html>
<head>
    <title>Dashboard & API Token Management</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 30px; background: #f4f6f8; color: #333; }
        .container { max-width: 650px; margin: auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h2 { margin-top: 0; color: #1e3a8a; }
        input, select { width: 100%; padding: 10px; font-size: 15px; box-sizing: border-box; margin-bottom: 12px; border: 1px solid #cbd5e1; border-radius: 4px; }
        button { padding: 10px 15px; font-size: 15px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        .token-item { background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 4px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
        .delete-btn { background: #dc2626; }
        .delete-btn:hover { background: #b91c1c; }
        #msg { margin-top: 10px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Secure Device Login</h2>
        <p>Enter the user code displayed on your CLI or TV application screen:</p>
        <input type="text" id="user_code" placeholder="CODE-1234" style="text-transform: uppercase;" />
        <button onclick="approveDevice()">Authorize Device</button>
        <p id="device_msg"></p>
    </div>

    <div class="container">
        <h2>Create API Token</h2>
        <p>Enter a name and select permissions scope for your new API token:</p>
        <input type="text" id="token_name" placeholder="Token Name (e.g. CLI Deploy Key)" />
        <label for="token_scopes"><strong>Select Scopes:</strong></label>
        <select id="token_scopes" multiple style="height: 80px; margin-top: 5px;">
            <option value="api.connectors.read" selected>api.connectors.read</option>
            <option value="api.connectors.invoke">api.connectors.invoke</option>
            <option value="offline_access">offline_access</option>
        </select>
        <button onclick="createApiToken()" style="margin-top: 10px;">Create API Token</button>
        <p id="token_create_msg"></p>
    </div>

    <div class="container">
        <h2>Active API Tokens</h2>
        <button onclick="loadApiTokens()" style="margin-bottom: 15px; background: #475569;">Refresh Token List</button>
        <div id="token_list">Loading tokens...</div>
    </div>

    <script>
        function approveDevice() {
            const code = document.getElementById('user_code').value.trim();
            fetch('/login/device/approve?user_code=' + encodeURIComponent(code), {method: 'POST'})
                .then(async res => {
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.error || "Authorization failed");
                    return data;
                })
                .then(data => {
                    document.getElementById('device_msg').style.color = "green";
                    document.getElementById('device_msg').innerText = data.message || "Authorized successfully!";
                }).catch(err => {
                    document.getElementById('device_msg').style.color = "red";
                    document.getElementById('device_msg').innerText = "Error: " + err.message;
                });
        }

        function createApiToken() {
            const name = document.getElementById('token_name').value.trim();
            const selectEl = document.getElementById('token_scopes');
            const scopes = Array.from(selectEl.selectedOptions).map(opt => opt.value);

            if (!name) {
                alert("Please enter a token name.");
                return;
            }

            fetch('/api-tokens/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name, scopes: scopes })
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById('token_create_msg').style.color = "green";
                document.getElementById('token_create_msg').innerText = "Created! Token: " + data.api_token;
                document.getElementById('token_name').value = "";
                loadApiTokens();
            })
            .catch(err => {
                document.getElementById('token_create_msg').style.color = "red";
                document.getElementById('token_create_msg').innerText = "Failed to create token.";
            });
        }

        function loadApiTokens() {
            fetch('/api-tokens/list')
                .then(res => res.json())
                .then(data => {
                    const listContainer = document.getElementById('token_list');
                    if (!data.tokens || data.tokens.length === 0) {
                        listContainer.innerHTML = "<p>No active API tokens found.</p>";
                        return;
                    }
                    let html = "";
                    data.tokens.forEach(t => {
                        html += '<div class="token-item"><div><strong>' + t.name + '</strong><br><small>ID: ' + t.id + ' | Scopes: ' + (t.scopes ? t.scopes.join(', ') : '') + '</small></div>' +
                                '<button class="delete-btn" onclick="deleteApiToken(\'' + t.id + '\')">Delete</button></div>';
                    });
                    listContainer.innerHTML = html;
                })
                .catch(err => {
                    document.getElementById('token_list').innerText = "Failed to load tokens.";
                });
        }

        function deleteApiToken(id) {
            if (!confirm("Are you sure you want to delete this API token?")) return;
            fetch('/api-tokens/delete?id=' + encodeURIComponent(id), { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    loadApiTokens();
                })
                .catch(err => alert("Failed to delete token."));
        }

        // Load tokens on initial page load
        window.onload = loadApiTokens;
    </script>
</body>
</html>`

func main() {
	// Initialize or load cryptographic JWT secret key from file
	initJWTSecretKey("jwt_secret.key")

	mux := http.NewServeMux()

	// 1. Host Registration & Metadata
	mux.HandleFunc("/api/host", handleHostRegistry)
	mux.HandleFunc("/list-routes", handleListRoutes)
	mux.HandleFunc("/.well-known/openid-configuration", handleWellKnown)
	mux.HandleFunc("/health", handleHealth)

	// 2. Account Auth Endpoints (Register, Login, Logout)
	mux.HandleFunc("/api/auth/register", handleAccountRegister)
	mux.HandleFunc("/api/auth/login", handleAccountLogin)
	mux.HandleFunc("/api/auth/logout", handleAccountLogout)

	// 3. API Token Management Subsystem
	mux.HandleFunc("/api-tokens/create", handleCreateAPIToken)
	mux.HandleFunc("/api-tokens/list", handleListAPITokens)
	mux.HandleFunc("/api-tokens/delete", handleDeleteAPIToken)

	// 4. OAuth Apps, Device & Token Flows
	mux.HandleFunc("/oauth/apps/create", handleCreateOAuthApp)
	mux.HandleFunc("/oauth/device", handleDeviceCodeGeneration)
	mux.HandleFunc("/login/device", handleLoginDevicePage)
	mux.HandleFunc("/login/device/approve", handleApproveDeviceCode)
	mux.HandleFunc("/oauth2/token", handleTokenExchange)
	mux.HandleFunc("/oauth2/token/device", handleTokenExchange)
	mux.HandleFunc("/oauth/authorize", handlePKCEAuthorize)

	// 5. User & Session Endpoints
	mux.HandleFunc("/oauth/userinfo", handleUserInfo)
	mux.HandleFunc("/api/whoami", handleWhoAmI)
	mux.HandleFunc("/api/oauth/status", handleOAuthStatus)

	// 6. VPN Management & 10.x IP Subsystem
	mux.HandleFunc("/api/vpn/countries", handleListCountries)
	mux.HandleFunc("/api/vpn/ip", handleGetVPNIP)
	mux.HandleFunc("/api/vpn/connect", handleConnectVPN)
	mux.HandleFunc("/api/vpn/fastest", handleConnectFastest)
	mux.HandleFunc("/api/vpn/disconnect", handleDisconnectVPN)
	mux.HandleFunc("/api/vpn/status", handleVPNStatus)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5900"
	}
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	fmt.Printf("🚀 REST API Server running on port %s (Crypto JWT, Accounts, API Tokens & VPN Ready)\n", port)
	if err := http.ListenAndServe(port, mux); err != nil {
		fmt.Printf("Server critical error: %v\n", err)
	}
}

// --- Cryptographic Secret Key Management ---

func initJWTSecretKey(filepath string) {
	if _, err := os.Stat(filepath); err == nil {
		data, readErr := os.ReadFile(filepath)
		if readErr == nil && len(data) > 0 {
			jwtSecret = data
			fmt.Println("🔑 Loaded existing JWT secret key from file:", filepath)
			return
		}
	}

	secretBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, secretBytes)
	if err != nil {
		panic("Failed to generate secure crypto random bytes for JWT secret")
	}

	jwtSecret = []byte(hex.EncodeToString(secretBytes))
	_ = os.WriteFile(filepath, jwtSecret, 0600)
	fmt.Println("🔒 Generated new crypto JWT secret key and saved to file:", filepath)
}

// --- Dedicated IP Generator Function ---

func generateVPNIP(countryCode string) string {
	seed := time.Now().UnixNano()
	return fmt.Sprintf("10.%d.%d.%d", (seed%100)+1, (seed%200)+1, (seed%250)+1)
}

// --- Helper Utilities ---

func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return scheme + "://" + host
	}
	if active, ok := hostRegistry.Load("active_host"); ok {
		return scheme + "://" + active.(string)
	}
	return scheme + "://" + r.Host
}

func generateRandomHex(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// --- Handlers: API Token Management Subsystem ---

func handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, `{"error": "invalid request body or missing token name"}`, http.StatusBadRequest)
		return
	}

	if len(req.Scopes) == 0 {
		req.Scopes = []string{"api.connectors.read"}
	}

	tokenId := "tk_" + generateRandomHex(6)
	tokenString := "gm_pat_" + generateRandomHex(16)

	record := APITokenRecord{
		ID:        tokenId,
		Name:      req.Name,
		Scopes:    req.Scopes,
		Token:     tokenString,
		CreatedAt: time.Now(),
	}

	apiTokenStore.Store(tokenString, record)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"token_id":  tokenId,
		"api_token": tokenString,
		"name":      req.Name,
		"scopes":    req.Scopes,
	})
}

func handleListAPITokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tokens []map[string]interface{}
	apiTokenStore.Range(func(key, value interface{}) bool {
		rec := value.(APITokenRecord)
		tokens = append(tokens, map[string]interface{}{
			"id":         rec.ID,
			"name":       rec.Name,
			"scopes":     rec.Scopes,
			"created_at": rec.CreatedAt,
		})
		return true
	})

	if tokens == nil {
		tokens = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":  len(tokens),
		"tokens": tokens,
	})
}

func handleDeleteAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenId := r.URL.Query().Get("id")
	if tokenId == "" {
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		tokenId = req.ID
	}

	if tokenId == "" {
		http.Error(w, `{"error": "missing token id"}`, http.StatusBadRequest)
		return
	}

	deleted := false
	apiTokenStore.Range(func(key, value interface{}) bool {
		rec := value.(APITokenRecord)
		if rec.ID == tokenId || key.(string) == tokenId {
			apiTokenStore.Delete(key)
			deleted = true
			return false
		}
		return true
	})

	if !deleted {
		http.Error(w, `{"error": "api token not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "API token successfully deleted",
	})
}

// --- Handlers: Account Auth Subsystem ---

func handleAccountRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Prompt   string `json:"prompt"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error": "username and password are required"}`, http.StatusBadRequest)
		return
	}

	if _, exists := userDatabase.Load(req.Username); exists {
		http.Error(w, `{"error": "account already exists"}`, http.StatusConflict)
		return
	}

	acc := Account{
		Username: req.Username,
		Password: req.Password,
		Prompt:   req.Prompt,
		Created:  time.Now(),
	}
	userDatabase.Store(req.Username, acc)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "success",
		"message":  "Account registered successfully",
		"username": req.Username,
	})
}

func handleAccountLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Prompt   string `json:"prompt"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	val, ok := userDatabase.Load(req.Username)
	if !ok {
		http.Error(w, `{"error": "invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	acc := val.(Account)
	if acc.Password != req.Password {
		http.Error(w, `{"error": "invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	// Generate Session Token
	token := "sess_" + generateRandomHex(16)
	activeSession.Store(token, req.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "success",
		"session_token": token,
		"username":      req.Username,
		"prompt":        acc.Prompt,
	})
}

func handleAccountLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.URL.Query().Get("token")
	}

	if token != "" {
		activeSession.Delete(token)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Successfully logged out from account session",
	})
}

// --- Handlers: Host & Discovery ---

func handleHostRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Host string `json:"host"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Host != "" {
			hostRegistry.Store("active_host", req.Host)
		}
	}
	activeHost, ok := hostRegistry.Load("active_host")
	if !ok {
		activeHost = r.Host
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"host":        activeHost,
		"server_time": time.Now().Format(time.RFC3339),
	})
}

func handleListRoutes(w http.ResponseWriter, r *http.Request) {
	routes := []string{
		"POST /api/host",
		"POST /api/auth/register",
		"POST /api/auth/login",
		"POST /api/auth/logout",
		"POST /api-tokens/create",
		"GET /api-tokens/list",
		"POST /api-tokens/delete",
		"POST /oauth/apps/create",
		"GET /.well-known/openid-configuration",
		"POST /oauth/device",
		"GET /login/device",
		"POST /login/device/approve",
		"POST /oauth2/token",
		"POST /oauth2/token/device",
		"GET /oauth/authorize",
		"GET /oauth/userinfo",
		"GET /api/whoami",
		"GET /api/oauth/status",
		"GET /api/vpn/countries",
		"GET /api/vpn/ip",
		"POST /api/vpn/connect",
		"POST /api/vpn/fastest",
		"POST /api/vpn/disconnect",
		"GET /api/vpn/status",
		"GET /health",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"routes": routes})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if sleepMs := r.URL.Query().Get("sleep_ms"); sleepMs != "" {
		if dur, err := time.ParseDuration(sleepMs + "ms"); err == nil {
			time.Sleep(dur)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "timestamp": time.Now().Format(time.RFC3339)})
}

func handleWellKnown(w http.ResponseWriter, r *http.Request) {
	base := getBaseURL(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"issuer":                        base,
		"authorization_endpoint":        base + "/oauth/authorize",
		"token_endpoint":                base + "/oauth2/token",
		"userinfo_endpoint":             base + "/oauth/userinfo",
		"device_authorization_endpoint": base + "/oauth/device",
		"scopes_supported": []string{
			"openid", "profile", "email", "offline_access",
			"api.connectors.read", "api.connectors.invoke",
		},
	})
}

// --- Handlers: OAuth Apps, Device Flow & JWT Token ---

func handleCreateOAuthApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AppName      string   `json:"app_name"`
		RedirectUris []string `json:"redirect_uris"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.AppName == "" {
		req.AppName = "Default VPN Client App"
	}

	clientID := "client_" + generateRandomHex(6)
	clientSecret := "cs_" + generateRandomHex(16)

	app := OAuthApp{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AppName:      req.AppName,
		RedirectUris: req.RedirectUris,
	}
	appDatabase.Store(clientID, app)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(app)
}

func handleDeviceCodeGeneration(w http.ResponseWriter, r *http.Request) {
	base := getBaseURL(r)
	clientID := r.FormValue("client_id")
	if clientID == "" {
		clientID = "default_cli_client"
	}
	scope := r.FormValue("scope")
	if scope == "" {
		scope = "openid profile email api.connectors.read api.connectors.invoke"
	}

	deviceCode := "gm_dev_" + generateRandomHex(12)
	userCode := fmt.Sprintf("CODE-%04d", time.Now().UnixNano()%10000)

	session := DeviceCodeSession{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		Status:     "pending",
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}
	deviceStore.Store(userCode, session)
	deviceStore.Store(deviceCode, session)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base + "/login/device",
		"verification_uri_complete": base + "/login/device?user_code=" + userCode,
		"expires_in":                900,
		"interval":                  5,
	})
}

func handleLoginDevicePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
}

func handleApproveDeviceCode(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		userCode = r.FormValue("user_code")
	}

	val, ok := deviceStore.Load(userCode)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_device_code"})
		return
	}

	session := val.(DeviceCodeSession)
	if time.Now().After(session.ExpiresAt) {
		deviceStore.Delete(userCode)
		deviceStore.Delete(session.DeviceCode)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "expired_device_code"})
		return
	}

	session.Status = "approved"
	deviceStore.Store(userCode, session)
	deviceStore.Store(session.DeviceCode, session)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Device successfully authorized!",
	})
}

func handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	base := getBaseURL(r)
	claims := jwt.MapClaims{
		"sub":           "usr_secure_9910",
		"iss":           base,
		"aud":           "api.connectors",
		"exp":           time.Now().Add(1 * time.Hour).Unix(),
		"organizations": []string{"Org-Alpha", "Org-Beta"},
		"scope":         "openid profile email offline_access api.connectors.read api.connectors.invoke",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to sign JWT token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  signedToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "rt_" + generateRandomHex(16),
		"id_token":      signedToken,
		"scope":         claims["scope"],
	})
}

func handlePKCEAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")

	if redirectURI == "" || codeChallenge == "" {
		http.Error(w, "Missing required PKCE parameters", http.StatusBadRequest)
		return
	}

	authCode := "ac_" + generateRandomHex(8)
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":            "usr_secure_9910",
		"name":           "Verified VPN Admin",
		"email":          "admin@secure-connector.net",
		"email_verified": true,
		"organizations":  []string{"Org-Alpha", "Org-Beta"},
	})
}

func handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"identity": "codex_cli_simplified_flow",
		"active":   true,
		"scope":    "api.connectors.read api.connectors.invoke",
	})
}

func handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"oauth_status": "active",
		"flow":         "PKCE & Device Grant Enabled",
	})
}

// --- Handlers: VPN Management & 10.x.x.x IP Generation ---

func handleListCountries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":     len(vpnCountries),
		"countries": vpnCountries,
	})
}

func handleGetVPNIP(w http.ResponseWriter, r *http.Request) {
	vpnState.Lock()
	defer vpnState.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"current_vpn_ip": vpnState.IP,
		"country":        vpnState.Country,
		"connected":      vpnState.Connected,
	})
}

func handleConnectVPN(w http.ResponseWriter, r *http.Request) {
	countryCode := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	if countryCode == "" {
		http.Error(w, `{"error": "country query parameter is required (e.g. ?country=US)"}`, http.StatusBadRequest)
		return
	}

	// Validate country code against supported list
	var foundCountry *Country
	for _, c := range vpnCountries {
		if c.Code == countryCode || strings.EqualFold(c.Name, countryCode) {
			foundCountry = &c
			break
		}
	}

	if foundCountry == nil {
		http.Error(w, `{"error": "unsupported or invalid country code"}`, http.StatusBadRequest)
		return
	}

	vpnState.Lock()
	defer vpnState.Unlock()

	vpnState.Connected = true
	vpnState.Country = foundCountry.Name + " (" + foundCountry.Code + ")"
	vpnState.IP = generateVPNIP(foundCountry.Code)
	vpnState.Speed = fmt.Sprintf("%d ms", foundCountry.Ping)
	vpnState.ConnectedAt = time.Now().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vpnState)
}

func handleConnectFastest(w http.ResponseWriter, r *http.Request) {
	vpnState.Lock()
	defer vpnState.Unlock()

	fastest := vpnCountries[6] // Switzerland
	vpnState.Connected = true
	vpnState.Country = fastest.Name + " (" + fastest.Code + ")"
	vpnState.IP = generateVPNIP(fastest.Code)
	vpnState.Speed = fmt.Sprintf("%d ms", fastest.Ping)
	vpnState.ConnectedAt = time.Now().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vpnState)
}

func handleDisconnectVPN(w http.ResponseWriter, r *http.Request) {
	vpnState.Lock()
	defer vpnState.Unlock()

	vpnState.Connected = false
	vpnState.Country = "None"
	vpnState.IP = "127.0.0.1"
	vpnState.Speed = "0 ms"
	vpnState.ConnectedAt = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vpnState)
}

func handleVPNStatus(w http.ResponseWriter, r *http.Request) {
	vpnState.Lock()
	defer vpnState.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"connected":    vpnState.Connected,
		"country":      vpnState.Country,
		"vpn_ip":       vpnState.IP,
		"speed":        vpnState.Speed,
		"connected_at": vpnState.ConnectedAt,
	})
}
