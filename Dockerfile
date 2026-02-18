# Stage 1: Build the frontend
FROM node:22-alpine AS frontend-builder

WORKDIR /frontend

# Install Bun
RUN npm install -g bun

RUN apk update && apk add --no-cache git
# Install dependencies (copy manifests first for better layer caching)
COPY frontend/package.json frontend/bun.lock* frontend/yarn.lock* ./
RUN bun install --ignore-scripts

# Copy the rest of the frontend source and build
COPY frontend/ ./
RUN bun run build

# Stage 2: Build the Go backend
FROM golang:1.25-alpine AS backend-builder

WORKDIR /app

ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=0
ENV GOOS=linux

# Download Go modules first for layer caching
COPY backend/go.mod backend/go.sum ./
RUN go mod download

# Copy the backend source
COPY backend/ ./

# Copy the compiled frontend into the embed directory
# go:embed all:frontend in backend/pkg/embed/frontend.go resolves
# relative to that file, so files must live at backend/pkg/embed/frontend/
COPY --from=frontend-builder /frontend/build/ ./pkg/embed/frontend/

# Build the binary
RUN go build -o /app/console-api ./cmd/api/

# Stage 3: Minimal runtime image
FROM alpine:3.21

RUN apk --no-cache add ca-certificates wget

WORKDIR /app

COPY --from=backend-builder /app/console-api .

EXPOSE 3000

ENTRYPOINT ["/app/console-api"]
