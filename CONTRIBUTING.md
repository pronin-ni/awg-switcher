# Contributing

Contributions are welcome through GitHub pull requests. Run `go test ./...`, `go test -race ./...`, and `go vet ./...` before submitting. Do not commit VPN profiles, credentials, private keys, certificates, generated runtime configs, or production settings. Add dependencies only when needed; pin them and update `DEPENDENCIES.md`, `licenses/`, and the SBOM. CI rejects unrecognized license families and scans for secrets. Contributions are submitted under the repository's MIT license; by submitting a contribution you confirm you have authority to do so.
