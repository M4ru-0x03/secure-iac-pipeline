# Secure IaC Pipeline

[![IaC security](https://github.com/M4ru-0x03/secure-iac-pipeline/actions/workflows/iac-security.yml/badge.svg?branch=main)](https://github.com/M4ru-0x03/secure-iac-pipeline/actions/workflows/iac-security.yml)

A CI pipeline that blocks cloud misconfigurations in Terraform **before** they are deployed. Every pull request is scanned with [Checkov](https://www.checkov.io/) and eight custom [OPA/Rego](https://www.openpolicyagent.org/) policies run through [Conftest](https://www.conftest.dev/). A violation fails the check and the findings are published as a readable table.

Everything is static analysis: no cloud account, no credentials, and `terraform apply` is never run.

![A pull request run blocked by the pipeline](docs/images/blocked-pr-run-overview.png)

## The problem

Infrastructure as code turns a misconfiguration into a one-line change: an SSH rule open to `0.0.0.0/0`, a bucket granted to `allUsers`, a VM running as an over-privileged service account. Caught in review it costs a comment; caught in production it costs an incident. Reviewers miss these, and generic scanners have gaps, such as organisation-specific rules (required labels) and some encryption requirements.

This project shows a gate that catches them automatically, explains why, and is itself tested.

## How it works

```mermaid
flowchart LR
    PR[Pull request] --> A[terraform fmt + validate]
    PR --> B[Checkov]
    PR --> C[Rego policies via Conftest]
    PR --> D[Regression check]
    A --> G{All checks pass?}
    B --> G
    C --> G
    D --> G
    G -- yes --> M[Merge allowed]
    G -- no --> X[Merge blocked, findings in job summary]
```

| Job | What it does |
|---|---|
| **Terraform fmt and validate** | `fmt -check`, `init -backend=false` and `validate` on both the fixed and the vulnerable code. No credentials needed. |
| **Checkov** | Scans `terraform/fixed/gcp` and writes failed checks to the job summary. |
| **Rego policies** | Runs the policy unit tests (`conftest verify`), then applies the policies to `terraform/fixed/gcp`. |
| **Scanners still catch the known-bad code** | Requires all 8 policies to fire on `terraform/vulnerable/gcp`, and Checkov to fail on it. A scanner that silently stops detecting would otherwise pass green. |

## Policies

Each policy has its own Rego package under [`policy/gcp/`](policy/gcp/) and unit tests next to it (46 in total), written before the policy itself.

| Policy | Blocks | Why it matters | Checkov equivalent |
|---|---|---|---|
| [`public_bucket`](policy/gcp/public_bucket.rego) | `allUsers` / `allAuthenticatedUsers` on a bucket (IAM member or binding) | Anyone on the internet can read the data | `CKV_GCP_28` |
| [`open_firewall`](policy/gcp/open_firewall.rego) | Ingress from `0.0.0.0/0` or `::/0` to SSH, RDP or all ports | Exposes administrative access to the internet | `CKV_GCP_2` and others |
| [`bucket_cmek`](policy/gcp/bucket_cmek.rego) | Bucket without a customer-managed KMS key | Key control, rotation and revocation stay with you | none found |
| [`primitive_role`](policy/gcp/primitive_role.rego) | `roles/owner`, `roles/editor`, `roles/viewer` at project level | Far broader than any single job needs | `CKV_GCP_117` |
| [`flow_logs`](policy/gcp/flow_logs.rego) | Subnet without `log_config` | No network telemetry for investigations | `CKV_GCP_26` |
| [`default_service_account`](policy/gcp/default_service_account.rego) | VM running as the default service account with the `cloud-platform` scope | A compromised VM can reach every API the account can | `CKV_GCP_30`, `CKV_GCP_31` |
| [`public_ip`](policy/gcp/public_ip.rego) | Instance with an `access_config` block | Gives the VM an external address | `CKV_GCP_40` |
| [`required_labels`](policy/gcp/required_labels.rego) | Buckets and VMs without non-empty `owner` and `environment` labels | Ownership and cost attribution | none found |

The last column comes from `checkov --list` on the pinned version (3.4.0). Two policies cover gaps there: bucket CMEK and organisation-specific labels.

## Before and after

[`terraform/vulnerable/gcp`](terraform/vulnerable/gcp) contains eight intentional flaws; [`terraform/fixed/gcp`](terraform/fixed/gcp) is the remediated version.

| | Vulnerable | Fixed |
|---|---|---|
| Rego policies | 9 violations (all 8 policies fire) | 0 |
| Checkov | 15 failed, 14 passed | 0 failed, 36 passed, 2 skipped with a written reason |

[Pull request #1](https://github.com/M4ru-0x03/secure-iac-pipeline/pull/1) reintroduces an open SSH rule and a public bucket into the fixed code. The run fails, and both scanners agree on the findings:

![Rego policies summary of the blocked run](docs/images/blocked-pr-rego-summary.png)

![Checkov summary of the blocked run](docs/images/blocked-pr-checkov-summary.png)

Reverting the change on the same branch turns every job green:

![The same pull request after the revert](docs/images/passing-pr-run-overview.png)

The regression job proves the scanners still see the known-bad code:

![Regression check summary](docs/images/regression-summary.png)

## Run it locally

Prerequisites (the versions CI uses):

- [Terraform](https://developer.hashicorp.com/terraform/install) 1.17.1
- Conftest 0.71.1: `bash scripts/install-conftest.sh 0.71.1` (verifies the SHA256 checksum)
- Checkov 3.4.0: `pip install checkov==3.4.0`

```bash
# Same checks as CI, against the remediated code (exits 0)
bash scripts/run-checks.sh

# Against the intentionally vulnerable code (exits 1 and lists the findings)
bash scripts/run-checks.sh terraform/vulnerable/gcp
```

Or one tool at a time:

```bash
conftest verify                                                         # policy unit tests
conftest test --all-namespaces --parser hcl2 terraform/vulnerable/gcp/*.tf
checkov -d terraform/vulnerable/gcp --framework terraform
```

`terraform init -backend=false` only downloads the provider plugin; no cloud credentials are involved.

## Repository layout

```
.github/workflows/iac-security.yml   CI pipeline
policy/gcp/                          Rego policies and their unit tests
terraform/vulnerable/gcp/            Known-bad Terraform (the "before")
terraform/fixed/gcp/                 Remediated Terraform (the "after")
scripts/                             Local runner and Conftest installer
docs/                                Evidence (Checkov output) and screenshots
```

## Design decisions

- **Static analysis only.** Conftest reads the HCL directly through its `hcl2` parser, so no plan or credentials are needed. The trade-off is that variables and modules are not resolved.
- **One Rego package per policy.** Tests are isolated and a policy can be disabled on its own. The cost is running `conftest test` with `--all-namespaces`.
- **Tests first, including the allowed cases.** Each policy has tests for what must be flagged and for what must pass (for example SSH from a private range, or a dedicated service account with the `cloud-platform` scope).
- **The pipeline tests itself.** The regression job guards against a policy that silently stops firing.
- **Pinned supply chain.** Tool versions are fixed, actions are pinned by commit SHA, the workflow token is read-only, and the Conftest download is checksum-verified.
- **Skips are written down.** Two Checkov checks are skipped inline in the Terraform with a reason: `CKV_GCP_62` on the bucket that receives the access logs (logging into itself would be circular), and `CKV_GCP_38` because a customer-supplied disk key is secret material that cannot live in a repository.

## Limitations

- Only Google Cloud resources are covered, and only the resource types listed above.
- Port ranges such as `20-30` are not expanded by `open_firewall`.
- Labels set through a variable (`labels = var.labels`) cannot be read statically and are reported as missing.
- `primitive_role` covers project-level IAM only, not folders or organisations.
- `flow_logs` checks that logging is enabled, not its sampling or aggregation settings.
- A firewall rule with `disabled = true` is still reported.
- Each file is evaluated on its own, so a rule that needs two resources together is not possible without Conftest's `--combine`.
- The Identity-Aware Proxy range in `terraform/fixed/gcp/network.tf` should be confirmed against Google's documentation before real use.

## License

[MIT](LICENSE)
