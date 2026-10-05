# ---- Stage 1: build the program ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# Copy dependency files first so Docker can cache the download step
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

# ---- Stage 2: small final image ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
# The server loads this policy file at startup (path is passed via -policy below)
COPY policy.yaml /policy.yaml
EXPOSE 80
ENTRYPOINT ["/server", "-addr", ":80", "-policy", "/policy.yaml"]
