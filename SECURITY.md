# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub private vulnerability reporting. Open the **Security** tab of this
repository and choose **Report a vulnerability**.

Include the version (`k8s-remediate-nis2 --version`), the steps to reproduce,
and the impact. We will confirm the report and tell you the next steps.

## Supported versions

Only the latest release gets security fixes.

## Scope

The tool reads scanner reports and writes text files. Bugs are in scope when a
crafted report can write outside the output directory or inject code into
generated files.
