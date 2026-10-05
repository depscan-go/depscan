
FROM golang:1.26-alpine AS build
WORKDIR /src


COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

RUN mkdir -p /out/scans


FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server

COPY --from=build --chown=nonroot:nonroot /out/scans /scans

COPY policy.yaml /policy.yaml

EXPOSE 8080

ENTRYPOINT ["/server", "-addr", ":8080", "-policy", "/policy.yaml", "-scan-root", "/scans"]