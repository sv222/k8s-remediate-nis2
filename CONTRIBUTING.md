# Contributing

## Build and test

```sh
make build
make vet
make fmt
make test
make fuzz
```

Or use Go directly: `go build ./...`, `go vet ./...`, `go test -race ./...`.
Run `gofmt -s -l .` and `go mod tidy` before you open a pull request.

`make fuzz` runs each native Go fuzz target for `FUZZTIME` (default 20s). A normal
`go test` runs only the seed corpora, so CI stays fast. Fuzz targets are in
`internal/prowler`, `internal/kubebench`, `internal/render` and `internal/out`.
If a fuzz run finds a crash, commit the file it writes under `testdata/fuzz/`.

`make tf-check` (needs Docker) runs `terraform fmt -check` and `terraform validate`
on the generated code of the test reports and of a random-ID corpus. `make policy-test`
checks the Kyverno policies with the Kyverno CLI.

## Add a mapping entry and template

1. Add a template under `templates/kyverno/` or `templates/terraform/`.
2. Add an entry to `mapping/mappings.yaml` with `scanner`, `check_id` (or
   `benchmark_ids` for kube-bench), `title`, `articles`, and `templates` or
   `shared_templates`. Use `guidance` when there is no code fix.
3. Add or update a test input in `cmd/testdata` and the golden files in
   `cmd/testdata/golden`.
4. Run `go test ./...` and check the output.

Add `follow_up` to an entry when the generated code leaves the risk open (for example
Audit-mode policies or an open security group rule). Add `caution` for side effects.
The evidence report uses them to set the status `follow-up required`.

Kyverno templates must be `ValidatingPolicy` (`policies.kyverno.io/v1`) and start in `Audit` mode.

## End-to-end test

`make e2e` (or `bash scripts/e2e.sh`) tests the AWS templates against a local
AWS emulator. It needs Docker and `python3`. It does not need AWS credentials,
Go, Terraform or Prowler on the host. It uses only dummy credentials.

The script starts one Floci container (pinned image), creates bad resources,
runs Prowler 5.45, runs `remediate`, runs `terraform validate`, `plan` and
`apply` against the emulator, and runs Prowler again. It then applies the
follow-up steps that the guidance text describes (revoke open security group
rules, narrow network ACL entries, change the EKS cluster). It fails if a
covered check still has a `FAIL` result. It removes its containers, network and
volume at the end.

- `E2E_PREFIX` sets the name prefix of containers and network (default `nrval`).
- `E2E_WORKDIR` sets the work directory (default `temp/e2e`).
- `E2E_KEEP=1` keeps the work directory, with scans, logs and `report.md`.

All image versions are pinned in `scripts/e2e.sh`. The Prowler image is pinned by digest. The workflow
`.github/workflows/e2e.yml` runs it by hand and once a week, not on every push.
The emulator is not AWS: a green run proves the generated code is valid and
that Prowler accepts the result, not that real AWS accepts every change.

## Mapping review

The NIS2, DORA and ISO 27001 mappings in `mapping/mappings.yaml` have not
been reviewed by legal or compliance experts. If you work in compliance, audit
or law, please review them. Open an issue or a pull request for any article
reference that is wrong, too broad or missing. DORA Art.9 applies only to
financial entities.

## Pull requests

- Every change needs tests.
- Keep pull requests small and focused.
- Use short commit messages in imperative mood.

## Code of conduct

See `CODE_OF_CONDUCT.md`.
