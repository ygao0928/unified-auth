FROM golang:1.23-bookworm AS build
WORKDIR /src/auth-center
COPY auth-center/go.mod auth-center/go.sum ./
RUN go mod download
COPY auth-center/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-center ./cmd/auth-center

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/auth-center /usr/local/bin/auth-center
COPY conformance/keys/jwks.json /conformance/keys/jwks.json
COPY conformance/keys/jwks-rotated.json /conformance/keys/jwks-rotated.json
USER nobody
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auth-center"]
