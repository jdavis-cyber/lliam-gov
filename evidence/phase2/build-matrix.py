#!/usr/bin/env python3
"""Phase 2 control-matrix builder — local-PDF extraction edition.

Source-of-truth for how the matrix was built.  Runs `pdftotext -layout`
against the source PDFs in /Volumes/WORKSPACE/3-Resources/ once, caches
the text, then regex-extracts each control's verbatim statement.  Zero
NotebookLM round-trips; runs in seconds.

Re-run to regenerate the CSV from scratch.  CSV is not hand-edited.

Usage:
  python3 evidence/phase2/build-matrix.py

Pivot rationale (2026-05-25):
  The first version of this script issued ~46 NotebookLM queries to
  ground the verbatim text.  Jerome flagged that as wasteful because
  the source PDFs are local — `pdftotext` + regex extracts the same
  text instantly with zero cloud cost.  Citations point at the local
  PDF path + page approximations (line numbers in the -layout output)
  which is a stronger evidence trail than "NotebookLM grounded this
  from source ID X".
"""
from __future__ import annotations

import csv
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

REPO = Path(__file__).resolve().parents[2]
RESOURCES = Path("/Volumes/WORKSPACE/3-Resources")
PDFTOTEXT = "/opt/homebrew/bin/pdftotext"
TXT_CACHE = REPO / "evidence" / "phase2" / ".pdftext-cache"
TXT_CACHE.mkdir(parents=True, exist_ok=True)

# Source PDFs (paths under /Volumes/WORKSPACE/3-Resources)
PDF_SP171_R2 = RESOURCES / "AI Governance and Compliance/NIST Frameworks/NIST_SP_800-171_r2.pdf"
PDF_SP171_R3 = RESOURCES / "AI Governance and Compliance/NIST Frameworks/NIST_SP_800-171_r3.pdf"
PDF_ISO27 = RESOURCES / "Program & Project Management/Integrated Management System/ISO 27001/ISO 27001-2022.pdf"
PDF_ISO42 = RESOURCES / "AI Governance and Compliance/ISO_42001-2023.pdf"


def extract_pdf(pdf_path: Path) -> Path:
    """Run pdftotext -layout once, cache the output."""
    out = TXT_CACHE / (pdf_path.stem + ".txt")
    if out.exists() and out.stat().st_mtime >= pdf_path.stat().st_mtime:
        return out
    subprocess.run(
        [PDFTOTEXT, "-layout", str(pdf_path), str(out)],
        check=True, capture_output=True,
    )
    return out


def clean(s: str) -> str:
    """Normalize whitespace from pdftotext -layout output.

    PDF -layout emits left-margin padding and column alignment that
    inflates leading spaces.  Strip leading spaces per line, drop
    headers/footers (page numbers, section repeats), collapse blank
    runs to a single blank.
    """
    lines = s.splitlines()
    # Drop the per-page header/footer signature lines (uppercase short lines
    # that repeat across the document).
    drop_patterns = [
        re.compile(r"^\s*CHAPTER\s+\w+\s*$"),
        re.compile(r"^\s*PAGE\s+\d+\s*$"),
        re.compile(r"^\s*SP\s+800-171,\s+REVISION\s+\d+.*$"),
        re.compile(r"^\s*PROTECTING\s+CONTROLLED\s+UNCLASSIFIED.*$"),
        re.compile(r"^\s*_{20,}\s*$"),
        re.compile(r"^\s*\f\s*$"),  # form-feed
    ]
    out = []
    blanks = 0
    for ln in lines:
        if any(p.match(ln) for p in drop_patterns):
            continue
        stripped = ln.rstrip()
        if not stripped.strip():
            blanks += 1
            if blanks <= 1:
                out.append("")
            continue
        blanks = 0
        # Dedent: find the shortest leading-space prefix
        out.append(re.sub(r"^\s{2,}", "  ", stripped))
    return "\n".join(out).strip()


def extract_between(txt: str, start_re: str, end_re: str, *, flags=re.MULTILINE) -> str:
    """Return text from the first match of start_re up to (not including) end_re.

    The end search starts strictly AFTER the start match's end position so a
    matching end_re cannot re-match the start match itself.
    """
    m_start = re.search(start_re, txt, flags=flags)
    if not m_start:
        return f"[NOT FOUND in source PDF: start_re={start_re!r}]"
    search_from = m_start.end()
    m_end = re.search(end_re, txt[search_from:], flags=flags)
    if not m_end:
        return txt[m_start.start(): m_start.start() + 4000]
    return txt[m_start.start(): search_from + m_end.start()].rstrip()


# ---------------------------------------------------------------------------
# Lliam-GOV §5 implementation owners
# ---------------------------------------------------------------------------
KEY_MGMT = "lliam_gov/security/key_manager.py"
AUDIT_LOG = "lliam_gov/security/audit_logger.py"
PRINCIPAL = "lliam_gov/security/principal.py"
CAPABILITIES = "lliam_gov/security/capabilities.py"
EGRESS = "lliam_gov/security/egress.py"
RUNTIME = "lliam_gov/security/runtime_guard.py"
SELFMOD = "lliam_gov/security/selfmod_gate.py"  # §5.5.bis
CUI = "lliam_gov/security/cui.py"
GATEWAY_TRIM = "gateway/platforms/{slack,email,telegram}.py (other adapters deleted)"
DASHBOARD = "hermes_cli/web_server.py + hermes_cli/main.py (loopback-only)"
SCA = "evidence/sbom/ + hermes_cli/security_advisories.py"
GOV_OPS = "GOVERNANCE_ONLY (Jerome as AIMS PM; Jack as authorizing reviewer)"

# Per-row data — the EXTRACTORS list defines (control_id, standard,
# source_pdf, extractor, owner, evidence_artifact, cross_mappings,
# rev3_equivalent_id, notes).  `extractor` is called as extractor(txt)
# and must return the verbatim section.


@dataclass
class Row:
    control_id: str
    standard: str
    pdf: Path
    extractor: Callable[[str], str]
    lliam_owner: str
    evidence_artifact: str
    cross_mappings: str
    rev3_equivalent: str = ""  # SP 800-171 only
    notes: str = ""
    current_state: str = "not_implemented"


def sp(req: str) -> Callable[[str], str]:
    """SP 800-171 R2 extractor: from '3.X.Y' to the next '3.A.B' or section."""
    # Match the control line starting with possibly leading whitespace
    # then "3.X.Y" followed by space and capital letter (the requirement text)
    # SP 800-171 r2 PDF has the IDs left-justified with lots of column padding.
    safe = re.escape(req)
    nxt = req.split(".")
    # Next number same family
    family = ".".join(nxt[:2]) + r"\.\d+"
    nxt_family = r"3\.\d+\s+[A-Z]"  # next section header e.g., "3.14 SYSTEM AND..."
    def extract(txt: str) -> str:
        # Find the control's section. Use re.MULTILINE.
        body = extract_between(
            txt,
            rf"^\s*{safe}\s+[A-Z]",  # "3.13.16 Protect ..."
            rf"(^\s*{family}\s+[A-Z]|^\s*{nxt_family})",
            flags=re.MULTILINE,
        )
        return body.strip()
    return extract


def sp_r3(req: str) -> Callable[[str], str]:
    """SP 800-171 R3 extractor: from '03.X.Y' format."""
    safe = re.escape(req)
    nxt_family = r"03\.\d+\s"
    family = ".".join(req.split(".")[:2]) + r"\.\d+"
    def extract(txt: str) -> str:
        body = extract_between(
            txt,
            rf"^\s*{safe}\s+[A-Z]",
            rf"(^\s*{family}\s+[A-Z]|^\s*{nxt_family})",
            flags=re.MULTILINE,
        )
        return body.strip()
    return extract


def iso27(ref_short: str) -> Callable[[str], str]:
    """ISO 27001:2022 Annex A — PDF uses '8.24' not 'A.8.24' format.

    ref_short is the PDF-internal form, e.g., '8.24'.
    """
    safe = re.escape(ref_short)
    # Next control: '8.25' OR next section
    parts = ref_short.split(".")
    nxt_minor = f"{parts[0]}.{int(parts[1])+1}" if len(parts) == 2 else ""
    def extract(txt: str) -> str:
        body = extract_between(
            txt,
            rf"^{safe}\s+\S",
            rf"^({re.escape(nxt_minor)}\s+\S|\d+\.\d+\s+\S)" if nxt_minor else r"\n\n\n",
            flags=re.MULTILINE,
        )
        return body.strip()
    return extract


def iso42(ref: str) -> Callable[[str], str]:
    """ISO 42001:2023 Annex A — uses 'A.X.Y' or 'A.X.Y.Z' format.

    Captures the control title + text.  ISO 42001 Annex A is presented
    as a 3-column table; pdftotext -layout preserves columns with heavy
    left-padding.  We capture from "A.X.Y  <Title>" up to the next
    sibling or any next Annex-A row.
    """
    safe = re.escape(ref)
    parts = ref.split(".")  # e.g., ['A', '4', '3'] or ['A', '6', '1', '2']

    # End boundary: any of these means we've left this row.
    end_alternatives: list[str] = []
    if len(parts) == 3:
        # A.X.Y → next is A.X.(Y+1) or A.(X+1).N
        end_alternatives.append(rf"A\.{parts[1]}\.{int(parts[2]) + 1}\s+\S")
        end_alternatives.append(rf"A\.{int(parts[1]) + 1}\.\d+\s+\S")
    elif len(parts) == 4:
        # A.X.Y.Z → next is A.X.Y.(Z+1) or A.X.(Y+1).N or A.(X+1).N
        end_alternatives.append(
            rf"A\.{parts[1]}\.{parts[2]}\.{int(parts[3]) + 1}\s+\S"
        )
        end_alternatives.append(
            rf"A\.{parts[1]}\.{int(parts[2]) + 1}\b"
        )
        end_alternatives.append(rf"A\.{int(parts[1]) + 1}\.\d+\s+\S")
    end_alternatives.append(r"Annex\s+B")

    end_re = r"^\s*(" + "|".join(end_alternatives) + r")"

    def extract(txt: str) -> str:
        return extract_between(
            txt, rf"^\s*{safe}\s+\S", end_re, flags=re.MULTILINE
        ).strip()
    return extract


# ---------------------------------------------------------------------------
# Row definitions — corrected against actual published standards
# ---------------------------------------------------------------------------
ROWS: list[Row] = [
    # ---- SP 800-171 Rev. 2 (CMMC L2 baseline) — 18 rows from plan §3.3 ----
    Row("SP800-171_3.1.1", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.1.1"),
        f"{PRINCIPAL} + gateway allowlists", "evidence/audit/principal-events.jsonl",
        "ISO 27001 A.8.5; ISO 42001 A.3.2", rev3_equivalent="03.01.01"),
    Row("SP800-171_3.1.2", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.1.2"),
        CAPABILITIES, "evidence/audit/tool-dispatch.jsonl",
        "ISO 27001 A.8.5", rev3_equivalent="03.01.02"),
    Row("SP800-171_3.1.13", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.1.13"),
        EGRESS, "evidence/audit/egress-events.jsonl",
        "ISO 27001 A.8.24", rev3_equivalent="03.01.13 (WITHDRAWN — moved to SC family in r3)",
        notes="r3 withdrew 3.1.13 — remote-access crypto moved to SC family"),
    Row("SP800-171_3.1.20", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.1.20"),
        EGRESS, "evidence/audit/egress-allowlist.yaml",
        "ISO 27001 A.8.20-A.8.23", rev3_equivalent="03.01.20"),
    Row("SP800-171_3.3.1", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.3.1"),
        AUDIT_LOG, "evidence/audit/tool-calls-*.jsonl + AEP exports",
        "ISO 27001 A.8.15; ISO 42001 Clause 7.5/9.1", rev3_equivalent="03.03.01"),
    Row("SP800-171_3.3.2", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.3.2"),
        f"{AUDIT_LOG} (principal field on every entry)",
        "evidence/audit/tool-calls-*.jsonl",
        "ISO 27001 A.8.15", rev3_equivalent="03.03.02"),
    Row("SP800-171_3.3.4", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.3.4"),
        f"{AUDIT_LOG} fail-closed branch",
        "tests/test_audit_logger.py::test_fail_closed",
        "ISO 27001 A.8.16", rev3_equivalent="03.03.04"),
    Row("SP800-171_3.3.8", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.3.8"),
        f"{AUDIT_LOG} (mode 0600, hash-chained)",
        "evidence/audit/chain-integrity-report.txt",
        "ISO 27001 A.8.15", rev3_equivalent="03.03.08"),
    Row("SP800-171_3.3.9", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.3.9"),
        "lliam-gov audit / rotate-key CLI ACL",
        "evidence/audit/cli-access-log.jsonl",
        "ISO 27001 A.8.5", rev3_equivalent="03.03.09"),
    Row("SP800-171_3.4.6", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.4.6"),
        f"{GATEWAY_TRIM} + {DASHBOARD}",
        "evidence/phase1/noise-floor-2026-05-25.md",
        "ISO 27001 A.8.20-A.8.23", rev3_equivalent="03.04.06", current_state="implemented"),
    Row("SP800-171_3.5.10", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.5.10"),
        f"{KEY_MGMT} (keyring-only secret store)",
        "evidence/audit/keychain-access.jsonl",
        "ISO 27001 A.5.17 / A.8.5", rev3_equivalent="03.05.10"),
    Row("SP800-171_3.8.9", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.8.9"),
        f"{KEY_MGMT} (AES-256-GCM on backups)",
        "evidence/audit/backup-encryption-test.txt",
        "ISO 27001 A.8.13; ISO 42001 A.4.3", rev3_equivalent="03.08.09"),
    Row("SP800-171_3.13.1", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.13.1"),
        f"{EGRESS} + {GATEWAY_TRIM}",
        "evidence/audit/boundary-controls.txt",
        "ISO 27001 A.8.20-A.8.23", rev3_equivalent="03.13.01"),
    Row("SP800-171_3.13.8", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.13.8"),
        f"{EGRESS} (TLS 1.2+, verify=True)",
        "evidence/audit/tls-policy-test.txt",
        "ISO 27001 A.8.24", rev3_equivalent="03.13.08"),
    Row("SP800-171_3.13.11", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.13.11"),
        f"{RUNTIME} (FIPS-OpenSSL hard gate)",
        "evidence/audit/fips-mode-startup-check.txt",
        "ISO 27001 A.8.24; FIPS 140-3", rev3_equivalent="03.13.11"),
    Row("SP800-171_3.13.16", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.13.16"),
        KEY_MGMT, "evidence/audit/at-rest-encryption-test.txt",
        "ISO 27001 A.8.24; ISO 42001 A.4.3", rev3_equivalent="03.13.16"),
    Row("SP800-171_3.14.2", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.14.2"),
        f"{SCA} + Katmai endpoint EDR (host-level)",
        "evidence/sbom/cyclonedx-*.json + evidence/audit/sca-review-*.md",
        "ISO 27001 A.8.7 / A.8.8", rev3_equivalent="03.14.02"),
    Row("SP800-171_3.14.3", "SP 800-171 Rev. 2", PDF_SP171_R2, sp("3.14.3"),
        f"{SCA} (quarterly cadence)",
        "evidence/audit/sca-review-*.md",
        "ISO 27001 A.5.7", rev3_equivalent="03.14.03"),

    # ---- ISO/IEC 42001:2023 Annex A — CORRECTED IDs (plan §3.4 had guesses) ----
    Row("ISO42001_A.3.2", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.3.2"),
        f"{PRINCIPAL} + AIMS RACI", "docs/governance/raci.md",
        "ISO 27001 A.5.2 / A.5.3",
        notes="Plan §3.4 cited A.10.2 'Allocation of responsibilities' — actual ID is A.3.2 'AI roles and responsibilities'"),
    Row("ISO42001_A.4.3", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.4.3"),
        f"{KEY_MGMT} + {CUI}", "evidence/audit/at-rest-encryption-test.txt",
        "SP 800-171 §3.13.16; ISO 27001 A.8.24",
        notes="Plan §3.4 cited A.8.4 'Data governance' — actual A.8.4 is 'Communication of incidents'; data governance lives at A.4.3 'Data resources'"),
    Row("ISO42001_A.5.2", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.5.2"),
        f"{SELFMOD} + docs/governance/impact-assessment.md",
        "docs/governance/impact-assessment.md", "—",
        notes="Plan §3.4 cited A.8.2 — actual ID is A.5.2 'AI system impact assessment'"),
    Row("ISO42001_A.6.1.2", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.6.1.2"),
        "docs/governance/control-matrix.md + plan §1",
        "docs/governance/control-matrix.md", "—",
        notes="Plan §3.4 cited A.9.2 — actual ID is A.6.1.2 'Objectives for responsible development of AI systems'"),
    Row("ISO42001_A.6.2.4", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.6.2.4"),
        SELFMOD, "evidence/audit/selfmod-events.jsonl", "—",
        notes="Plan §3.4 cited A.6.2.4 'Concepts' — actual A.6.2.4 is 'AI system verification and validation'. Most relevant to selfmod gate."),
    Row("ISO42001_A.6.2.6", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.6.2.6"),
        f"{SELFMOD} + {AUDIT_LOG}",
        "evidence/audit/operation-monitoring-*.md", "—",
        notes="Added by Phase 2 review — A.6.2.6 'AI system operation and monitoring' covers Lliam-GOV's runtime monitoring posture"),
    Row("ISO42001_A.6.2.8", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.6.2.8"),
        AUDIT_LOG, "evidence/audit/tool-calls-*.jsonl",
        "ISO 27001 A.8.15; SP 800-171 §3.3.1",
        notes="Added by Phase 2 review — A.6.2.8 'AI system recording of event logs' is the direct AIMS counterpart to the audit log"),
    Row("ISO42001_A.7.4", "ISO/IEC 42001:2023", PDF_ISO42, iso42("A.7.4"),
        f"{AUDIT_LOG} + {SCA}", "evidence/audit/data-quality-events.jsonl",
        "ISO 27001 A.5.34",
        notes="Plan cited 'Quality of system and data'; actual title is 'Quality of data for AI systems'"),

    # ---- ISO/IEC 42001:2023 body clauses (plan §3.4) ----
    # Body-clause extractors: anchor to end-of-line on the section header
    # so we skip the table-of-contents (which has ". ........... 15" trailers)
    # and land on the actual section body.
    Row("ISO42001_Clause_4", "ISO/IEC 42001:2023", PDF_ISO42,
        lambda t: extract_between(t, r"^\s*4\s+Context of the organization\s*$", r"^\s*5\s+Leadership\s*$", flags=re.MULTILINE),
        "AIMS scope (Katmai-owned)", "docs/governance/aims-scope.md", "—",
        notes="Body clause, not Annex A"),
    Row("ISO42001_Clause_6", "ISO/IEC 42001:2023", PDF_ISO42,
        lambda t: extract_between(t, r"^\s*6\s+Planning\s*$", r"^\s*7\s+Support\s*$", flags=re.MULTILINE),
        "Hardening overlay design", "docs/governance/control-matrix.md",
        "ISO 27001 Clause 6", notes="Body clause"),
    Row("ISO42001_Clause_7.5", "ISO/IEC 42001:2023", PDF_ISO42,
        lambda t: extract_between(t, r"^\s*7\.5\s+Documented information\s*$", r"^\s*8\s+Operation\s*$", flags=re.MULTILINE),
        f"{AUDIT_LOG} + this matrix + NOTICE",
        "evidence/* tree", "ISO 27001 Clause 7.5", notes="Body clause"),
    Row("ISO42001_Clause_8", "ISO/IEC 42001:2023", PDF_ISO42,
        lambda t: extract_between(t, r"^\s*8\s+Operation\s*$", r"^\s*9\s+Performance evaluation\s*$", flags=re.MULTILINE),
        "Hardening overlay live operation", "evidence/audit/*",
        "ISO 27001 Clause 8", notes="Body clause"),
    Row("ISO42001_Clause_9.1", "ISO/IEC 42001:2023", PDF_ISO42,
        lambda t: extract_between(t, r"^\s*9\.1\s+Monitoring,\s+measurement,\s+analysis\s+and\s+evaluation\s*$", r"^\s*9\.2", flags=re.MULTILINE),
        f"{SCA} + audit log review",
        "evidence/audit/sca-review-*.md", "ISO 27001 Clause 9.1", notes="Body clause"),
    Row("ISO42001_Clause_10", "ISO/IEC 42001:2023", PDF_ISO42,
        lambda t: extract_between(t, r"^\s*10\s+Improvement\s*$", r"^\s*Annex\s+A", flags=re.MULTILINE),
        "Quarterly improvement cycle",
        "docs/governance/improvement-log.md", "ISO 27001 Clause 10", notes="Body clause"),

    # ---- ISO/IEC 27001:2022 Annex A — PDF uses 'X.Y' not 'A.X.Y' ----
    Row("ISO27001_A.5.7", "ISO/IEC 27001:2022", PDF_ISO27, iso27("5.7"),
        SCA, "evidence/audit/sca-review-*.md",
        "SP 800-171 §3.14.3"),
    Row("ISO27001_A.5.20", "ISO/IEC 27001:2022", PDF_ISO27, iso27("5.20"),
        f"{SCA} + NOTICE (Hermes is primary supplier)",
        "NOTICE + evidence/sbom/cyclonedx-*.json", "—"),
    Row("ISO27001_A.5.21", "ISO/IEC 27001:2022", PDF_ISO27, iso27("5.21"),
        f"{SCA} + quarterly Hermes review",
        "evidence/audit/sca-review-*.md + evidence/audit/upstream-cherrypicks-*.md", "—"),
    Row("ISO27001_A.5.22", "ISO/IEC 27001:2022", PDF_ISO27, iso27("5.22"),
        "Quarterly Hermes CHANGELOG review",
        "evidence/audit/upstream-review-*.md", "—"),
    Row("ISO27001_A.5.23", "ISO/IEC 27001:2022", PDF_ISO27, iso27("5.23"),
        "Operator runbook (model-endpoint posture)",
        "docs/operate/model-endpoints.md", "—"),
    Row("ISO27001_A.5.31", "ISO/IEC 27001:2022", PDF_ISO27, iso27("5.31"),
        GOV_OPS, "docs/governance/legal-mapping.md", "—"),
    Row("ISO27001_A.5.32", "ISO/IEC 27001:2022", PDF_ISO27, iso27("5.32"),
        "NOTICE + LICENSE (MIT compliance)",
        "NOTICE + LICENSE", "—", current_state="implemented"),
    Row("ISO27001_A.6.3", "ISO/IEC 27001:2022", PDF_ISO27, iso27("6.3"),
        "docs/operate/* operator runbook",
        "docs/operate/", "—"),
    Row("ISO27001_A.8.5", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.5"),
        f"{PRINCIPAL} + gateway Bearer/HMAC",
        "evidence/audit/auth-events.jsonl", "SP 800-171 §3.1.1 / §3.1.2"),
    Row("ISO27001_A.8.6", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.6"),
        f"{AUDIT_LOG} monthly rotation + capacity check",
        "evidence/audit/capacity-checks-*.md", "—"),
    Row("ISO27001_A.8.8", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.8"),
        SCA, "evidence/audit/sca-review-*.md",
        "SP 800-171 §3.14.2"),
    Row("ISO27001_A.8.10", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.10"),
        f"{CUI} on-delete sanitization",
        "evidence/audit/deletion-events.jsonl", "—"),
    Row("ISO27001_A.8.11", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.11"),
        f"{AUDIT_LOG} params_hash pattern",
        "tests/test_audit_logger.py::test_no_raw_params", "—"),
    Row("ISO27001_A.8.12", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.12"),
        f"{EGRESS} allowlist + {CUI} marking",
        "evidence/audit/egress-events.jsonl + evidence/audit/cui-access-*.jsonl", "—"),
    Row("ISO27001_A.8.15", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.15"),
        AUDIT_LOG, "evidence/audit/tool-calls-*.jsonl",
        "SP 800-171 §3.3.1 / §3.3.2 / §3.3.8"),
    Row("ISO27001_A.8.16", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.16"),
        f"{AUDIT_LOG} review cadence",
        "evidence/audit/audit-log-review-*.md", "SP 800-171 §3.3.4"),
    Row("ISO27001_A.8.20", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.20"),
        f"{EGRESS} + {GATEWAY_TRIM}",
        "evidence/audit/boundary-controls.txt",
        "SP 800-171 §3.13.1", current_state="scaffolded"),
    Row("ISO27001_A.8.21", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.21"),
        f"{EGRESS} (TLS 1.2+, verify=True)",
        "evidence/audit/tls-policy-test.txt", "—"),
    Row("ISO27001_A.8.22", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.22"),
        DASHBOARD, "evidence/audit/dashboard-bind-test.txt", "—",
        current_state="implemented"),
    Row("ISO27001_A.8.23", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.23"),
        f"{EGRESS} allowlist", "evidence/audit/egress-events.jsonl", "—"),
    Row("ISO27001_A.8.24", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.24"),
        f"{KEY_MGMT} + {RUNTIME} FIPS gate",
        "evidence/audit/at-rest-encryption-test.txt + evidence/audit/fips-mode-startup-check.txt",
        "SP 800-171 §3.13.11 / §3.13.16; ISO 42001 A.4.3"),
    Row("ISO27001_A.8.28", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.28"),
        "Hermes upstream practice + PR review",
        "(upstream CONTRIBUTING.md + repo PR review)", "—"),
    Row("ISO27001_A.8.30", "ISO/IEC 27001:2022", PDF_ISO27, iso27("8.30"),
        "Hermes upstream lineage", "NOTICE", "—", current_state="implemented"),
]


def main() -> int:
    print("Extracting source PDFs...", file=sys.stderr)
    pdf_texts: dict[str, str] = {}
    for pdf in [PDF_SP171_R2, PDF_SP171_R3, PDF_ISO27, PDF_ISO42]:
        if not pdf.exists():
            print(f"  MISSING: {pdf}", file=sys.stderr)
            return 1
        txt_path = extract_pdf(pdf)
        pdf_texts[str(pdf)] = clean(txt_path.read_text())
        print(f"  {pdf.name}: {len(pdf_texts[str(pdf)]):,} chars", file=sys.stderr)

    # Extract SP 800-171 r3 cross-mappings
    r3_text = pdf_texts[str(PDF_SP171_R3)]

    out = []
    print(f"\nExtracting {len(ROWS)} controls...", file=sys.stderr)
    for r in ROWS:
        txt = pdf_texts[str(r.pdf)]
        verbatim = r.extractor(txt)
        if not verbatim or verbatim.startswith("[NOT FOUND"):
            print(f"  ✗ {r.control_id}: {verbatim[:80]}", file=sys.stderr)
        else:
            print(f"  ✓ {r.control_id}: {len(verbatim)}b", file=sys.stderr)

        # If this is a SP 800-171 r2 row, also extract the r3 equivalent if defined
        rev3_text = ""
        if r.rev3_equivalent and not r.rev3_equivalent.startswith("03.01.13"):
            r3_id = r.rev3_equivalent.split(" ", 1)[0]
            extractor3 = sp_r3(r3_id)
            r3_extracted = extractor3(r3_text)
            if r3_extracted and not r3_extracted.startswith("[NOT FOUND"):
                rev3_text = r3_extracted[:2000]

        out.append({
            "control_id": r.control_id,
            "standard": r.standard,
            "statement_verbatim": verbatim,
            "source_pdf": r.pdf.name,
            "rev3_equivalent_id": r.rev3_equivalent,
            "rev3_statement_verbatim": rev3_text,
            "lliam_owner": r.lliam_owner,
            "evidence_artifact": r.evidence_artifact,
            "cross_mappings": r.cross_mappings,
            "current_state": r.current_state,
            "notes": r.notes,
        })

    out_csv = REPO / "evidence" / "control-matrix.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(out[0].keys()), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(out)
    print(f"\nWrote {out_csv} ({len(out)} rows)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
