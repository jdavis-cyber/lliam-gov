# Lliam-GOV — Intended Use, Mission Scope & Prohibited Uses (LG-GV-02)

| Field | Value |
|---|---|
| Document | Authorized Intended-Use / Unacceptable-Use Statement |
| Owner | Lliam-GOV Program |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Control | LG-GV-02 (document mission scope, intended use, prohibited/unacceptable uses) |
| Status | 0.1 DRAFT — Pending approval |

This statement defines what Lliam-GOV (a governance-hardened fork of Hermes Agent,
Nous Research, MIT) **is authorized to do**, and what it must **never** do, in a
U.S. federal/defense environment that processes Controlled Unclassified
Information (CUI). It is the human-readable companion to the enforced controls in
`cli-config.gov.yaml` + `policy/*.yaml`; the CI gates and runtime posture enforce
these boundaries mechanically.

---

## 1. Authorized mission scope

Lliam-GOV is authorized, under the strict gov posture (`security.posture: strict`),
to act as an **AI coding / analysis / operations assistant** within an accredited
CUI boundary:

- **Software engineering** — read, write, edit, and run code within the configured
  workspace (`HERMES_WRITE_SAFE_ROOT`), in the **sandboxed** execution backend
  (`terminal.backend: docker`).
- **Document & data analysis** over CUI-marked inputs, with markings preserved and
  secret/PII redaction on.
- **Inference** routed only to **approved, in-boundary providers** (FedRAMP/IL or
  on-prem local inference) — never to unauthorized/foreign endpoints.
- **Bounded tool use** — file, search, web (allowlisted), and sandboxed shell,
  with high-risk/irreversible actions routed to an authenticated human approver
  (graduated enforcement, not blanket-deny).

## 2. Intended users

Authenticated, authorized operators (and named approver/auditor roles) operating
within the accredited boundary. Single-operator and supervised-autonomy use are
in scope; fully-unattended high-risk automation is out of scope unless an approver
context exists (`deny_on_no_approver: true`).

## 3. Prohibited / unacceptable uses

The following are **categorically prohibited** in any CUI profile and are enforced
(deny-tier / fail-closed) — they are never re-enabled by a toggle or a deviation:

- **`godmode`** (Parseltongue / GODMODE / ULTRAPLINIAN) and **`obliteratus`**
  (weight-abliteration) — jailbreak / model-safety-bypass skills. **MANDATORY
  must-disable**; excluded in the Statement of Applicability. (LG-SC-01)
- **Offensive/dual-use tooling** (`web-pentest`, `sherlock`, `oss-forensics`)
  outside an authorized, scoped, time-boxed assessment in a **separate non-CUI**
  profile recorded in the deviation register. (LG-SC-01 / LG-CH-08)
- **Routing CUI to non-approved / foreign inference providers** (data spillage). (LG-MP)
- **Disabling safety guards** — `--yolo` / `HERMES_YOLO_MODE`, `approvals.mode: off`,
  `tirith_fail_open: true`, `allow_private_urls: true`, `allow_lazy_installs: true`
  in a CUI profile. (LG-CH-02 / LG-SD-06)
- **Hardline destructive ops** (`rm -rf /`, `mkfs`, `dd` to raw device, fork bomb,
  shutdown) and `sudo`-via-stdin — unconditional blocks. (LG-HO-03)
- **Writing to credential stores / system-auth paths** (`~/.ssh`, `~/.aws`,
  `~/.gnupg`, `/etc/sudoers|passwd|shadow`, `.env`). (LG-AZ-04)
- **Runtime self-install** of un-vetted packages / backends (air-gap). (LG-SS-07)
- **Exfiltration** of CUI/secrets to unapproved sinks (DLP taint gate). (LG-DP-10)

## 4. Graduated enforcement (capability preserved)

Within scope, enforcement is graduated, not blanket-deny: low-risk reads **allow**,
medium-risk mutations **log**, high-risk/irreversible actions are **HITL-approved**,
and only the categorically-unsafe operations above are **hard-denied**. The agent
remains a fully useful coding/analysis/ops assistant.

## 5. Deviations

Any departure from this statement or the hardened baseline requires an approved,
recorded entry in [`deviation-register.md`](deviation-register.md) (LG-CH-08).
`godmode` and `obliteratus` are **never eligible** for a CUI deviation.

---
*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
