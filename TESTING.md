# Testing

Required validation commands:

```sh
go test ./...
go test -race ./...
go test ./... -coverprofile=coverage.out
go vet ./...
```

The repository includes tests for:

- config loading, env resolution, validation, and redaction
- forwarded client-certificate info parsing and PEM validation
- hashed one-time authorization code storage
- rate limiting
- end-to-end authorize -> token -> userinfo flows
- logout safety and invalid request handling
- fuzz coverage for cert-info parsing, redirect matching, and scope parsing
