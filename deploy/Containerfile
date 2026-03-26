FROM docker.io/golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /verify-cmp ./cmd/verify-cmp/

FROM cgr.dev/chainguard/static:latest
COPY --from=builder /verify-cmp /usr/local/bin/verify-cmp
COPY deploy/plugin.yaml /home/argocd/cmp-server/config/plugin.yaml
USER 999
ENTRYPOINT ["/usr/local/bin/verify-cmp"]
