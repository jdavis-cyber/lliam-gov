# Bill of Materials — Supply-Chain Evidence  [P3.4 / LG-SS-05, IN-02/03]

- **ai-bom.yaml** — machine-readable AI inventory (providers / models / MCP
  servers / skills), reconciled from the P3 policy artifacts. Stable,
  repo-derived; committed as evidence of record.
- **sbom.json** — CycloneDX SBOM of the installed Python distributions.
  Environment-specific and regenerated **per build/release** (not committed
  here). Produce it with:

      python ci/governance-ci-gates/generate_bom.py evidence/bom

  The `sbom-ai-bom` CI job (governance-gates.yml, when CI runs) retains it as a
  build artifact.
