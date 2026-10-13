# Contributing

## Build and test

```sh
make build
make vet
make fmt
make test
```

Or use Go directly: `go build ./...`, `go vet ./...`, `go test -race ./...`.
Run `gofmt -l .` and `go mod tidy` before you open a pull request.

## Add a mapping entry and template

1. Add a template under `templates/kyverno/` or `templates/terraform/`.
2. Add an entry to `mapping/mappings.yaml` with `scanner`, `check_id` (or
   `benchmark_ids` for kube-bench), `title`, `articles`, and `templates` or
   `shared_templates`. Use `guidance` when there is no code fix.
3. Add or update a test input in `cmd/testdata` and the golden files in
   `cmd/testdata/golden`.
4. Run `go test ./...` and check the output.

Kyverno templates must start in `Audit` mode.

## Pull requests

- Every change needs tests.
- Keep pull requests small and focused.
- Use short commit messages in imperative mood.

## Code of conduct

See `CODE_OF_CONDUCT.md`.
