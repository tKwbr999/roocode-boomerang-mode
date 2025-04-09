# Stage 1: Build the application binary
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies if needed (e.g., for CGO)
# RUN apk add --no-cache gcc musl-dev

# Copy go module files
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
# CGO_ENABLED=0 for static linking (optional, depends on needs)
# -ldflags="-w -s" for smaller binary size (optional)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/bin/api /app/cmd/api/main.go

# Stage 2: Create the final lightweight image
FROM alpine:3.18

WORKDIR /app

# Install runtime dependencies if needed (e.g., ca-certificates for HTTPS)
RUN apk add --no-cache ca-certificates tzdata

# Copy the binary from the builder stage
COPY --from=builder /app/bin/api .

# Copy migration files if they need to be run from the container (optional)
# COPY --from=builder /app/internal/infrastructure/database/migration ./migration

# Copy configuration files or templates if needed
# COPY config.yml .

# Set the entrypoint user (optional, for security)
# RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# USER appuser

# Expose the application port
EXPOSE 8080

# Define the command to run the application
CMD ["/app/api"]
