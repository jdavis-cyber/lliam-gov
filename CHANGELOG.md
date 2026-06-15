# Changelog

All notable changes to Lliam-GOV are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Lliam-GOV is a governance-hardened fork of [Hermes Agent](https://github.com/NousResearch/hermes-agent)
> (Nous Research, MIT). Upstream release notes are preserved under
> [`docs/upstream/`](docs/upstream/).

## [Unreleased]

### Added
- Public-ready README with Lliam-GOV brand identity, monochrome banner, and a
  governance-led overview.
- Lliam-GOV security policy (`SECURITY.md`) — supported versions, private
  vulnerability reporting, trust model, and governance posture.
- Lliam-GOV contributing guide (`CONTRIBUTING.md`) for the governed-fork model
  with the verified dev-setup and local-green workflow.
- `CODE_OF_CONDUCT.md` and this `CHANGELOG.md`.
- Lliam-GOV-branded GitHub issue and pull-request templates.

### Changed
- `LICENSE` retains the upstream MIT © Nous Research notice and adds the
  Lliam-GOV copyright line.
- Relocated upstream Hermes documentation (release notes, `README.zh-CN`,
  upstream `CONTRIBUTING`) under `docs/upstream/` to tidy the repository root.

### Deferred
- Internal `hermes → lliam-gov` source rename (CLI prog-name, `hermes-ink`
  package, internal modules) — tracked in Linear **AI-341** to avoid risk to the
  install/run flow.

---

_Earlier history corresponds to the upstream Hermes Agent lineage; see
[`docs/upstream/`](docs/upstream/)._
