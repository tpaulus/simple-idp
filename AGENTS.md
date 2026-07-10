# Agent notes

This repository keeps configuration file-based and resolves `ENV:` references only inside `internal/config`.

Forwarded client-certificate parsing and PEM validation live in `internal/certauth`.

The in-memory authorization code store means the Kubernetes example deploys a single replica.
