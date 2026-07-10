FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/simple-idp ./cmd/simple-idp

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/tpaulus/simple-idp" \
      org.opencontainers.image.description="Tiny OIDC provider backed by forwarded mTLS identity" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=builder /out/simple-idp /simple-idp
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/simple-idp"]
