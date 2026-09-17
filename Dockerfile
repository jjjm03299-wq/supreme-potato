FROM golang:alpine

# Install wget and git for fetching dependencies
RUN apk add --no-cache wget git

# Set working directory inside the container
WORKDIR /app

# Download main.go directly from your GitHub repository
RUN wget https://raw.githubusercontent.com/jjjm03299-wq/supreme-potato/refs/heads/main/main.go

# Initialize Go module and fetch the required JWT package
RUN go mod init main && go get github.com/golang-jwt/jwt/v5

# Build the Go application binary
RUN go build -o main main.go

# Define environment variables (Port will be picked up by os.Getenv("PORT"))
ENV PORT=5900

# Expose the application port
EXPOSE 5900

# Run the compiled application
CMD ["./main"]
