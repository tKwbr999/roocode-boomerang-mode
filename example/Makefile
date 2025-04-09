# Load environment variables from .env file
include .env
export $(shell sed 's/=.*//' .env)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=api
BINARY_UNIX=$(BINARY_NAME)

# Default target
all: help

# Help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  run-dev          Run the development server"
	@echo "  build            Build the application binary"
	@echo "  test             Run tests"
	@echo "  test-coverage    Run tests with coverage report"
	@echo "  migrate-up       Apply database migrations (up)"
	@echo "  migrate-down     Revert database migrations (down)"
	@echo "  migrate-create   Create a new migration file (usage: make migrate-create name=your_migration_name)"
	@echo "  lint             Run linter (golangci-lint)"
	@echo "  swagger          Generate Swagger documentation"
	@echo "  docker-build     Build Docker image"
	@echo "  docker-up        Start services with Docker Compose"
	@echo "  docker-down      Stop services with Docker Compose"
	@echo "  docker-logs      View logs from Docker Compose services"
	@echo "  clean            Remove build artifacts"

# Run development server
run-dev:
	@echo "Starting development server..."
	$(GOCMD) run cmd/api/main.go

# Build application binary
build:
	@echo "Building application..."
	$(GOBUILD) -o bin/$(BINARY_UNIX) cmd/api/main.go

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -coverprofile=coverage.out ./...
	@echo "Generating HTML coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Database migration commands
DB_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSL_MODE}"
MIGRATE_PATH=internal/infrastructure/database/migration

migrate-up:
	@echo "Applying database migrations (up)..."
	migrate -path $(MIGRATE_PATH) -database "$(DB_URL)" up

migrate-down:
	@echo "Reverting database migrations (down)..."
	migrate -path $(MIGRATE_PATH) -database "$(DB_URL)" down

migrate-create:
	@if [ -z "$(name)" ]; then \
		echo "Migration name is required. Usage: make migrate-create name=your_migration_name"; \
		exit 1; \
	fi
	@echo "Creating migration file: $(name)..."
	migrate create -ext sql -dir $(MIGRATE_PATH) -seq $(name)

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

# Generate Swagger documentation
swagger:
	@echo "Generating Swagger documentation..."
	swag init -g cmd/api/main.go -o docs

# Docker commands
docker-build:
	@echo "Building Docker image..."
	docker-compose build api

docker-up:
	@echo "Starting services with Docker Compose..."
	docker-compose up -d

docker-down:
	@echo "Stopping services with Docker Compose..."
	docker-compose down

docker-logs:
	@echo "Viewing logs..."
	docker-compose logs -f

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	$(GOCLEAN)
	rm -f bin/$(BINARY_UNIX)
	rm -f coverage.out coverage.html
	rm -rf docs/

.PHONY: all help run-dev build test test-coverage migrate-up migrate-down migrate-create lint swagger docker-build docker-up docker-down docker-logs clean
