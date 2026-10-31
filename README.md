# Secure IaC Pipeline

A CI pipeline that blocks cloud misconfigurations in Terraform before they reach deployment, using Checkov and custom OPA/Rego policies run with Conftest.

> Work in progress. All analysis is static: no cloud account is used and nothing is ever applied.
