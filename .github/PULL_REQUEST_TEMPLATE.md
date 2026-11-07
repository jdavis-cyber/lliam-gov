<!-- AIMS-CHK-001 Code Review Checklist, Rev 1.0 (2026-11-06). The completed checklist on this pull request is the code review record (ISO/IEC 42001 Clause 8.1, Annex A.6.2.3, A.6.2.4). Tick each check, or mark it N/A with the reason. A "No" needs a remark and a priority (P1 fix before merge, P2 this iteration, P3 backlog). -->

## What changed and why

<!-- Link the requirement, defect or task this addresses. -->

## AIMS-CHK-001 Code review checklist

### 1. The pull request
- [ ] 1. The pull request says what changed and why, and links the requirement, defect or task it addresses.
- [ ] 2. Automated tests and build checks (CI) pass on this pull request. CI run:
- [ ] 3. The dependency scan (for example OSV) passes with no unwaived findings, or N/A with the reason.
- [ ] 4. Every review finding is fixed and re-reviewed before merge.
- [ ] 5. The AI System Owner approves the merge, with no unresolved blocking defect.

### 2. Code quality and security
- [ ] 6. The code is readable: clear names, current comments, no leftover debug or dead code.
- [ ] 7. Errors are handled safely: nothing fails silently and no error message exposes internal details.
- [ ] 8. No secrets, credentials or hard-coded settings are in the code or committed configuration; secrets load from outside the repository at run time.
- [ ] 9. Input from users, files, web pages and tools is checked and treated as data, never as instructions (prompt injection).

### 3. AI and governance (when the change touches an AI system, an agent tool or a governance control; otherwise N/A)
- [ ] 10. Every model request stays on a provider approved for the current configuration; any change of provider, model, system prompt or model settings goes through the change route (AIMS-005).
- [ ] 11. No way is added to train or fine-tune a model or build a training dataset, and the provider account's training setting stays off (AIMS-002).
- [ ] 12. No path is added by which restricted information (proprietary, CUI, CDI, classified or customer data) can reach the model, a tool or a connector (AIMS-002).
- [ ] 13. Every action added or altered that sends, publishes, deletes, buys or changes a system still stops for a person's approval, with no new bypass (AIMS-002).
- [ ] 14. The agent gets only the tools, file locations and connector access its task needs (AIMS-002).
- [ ] 15. AI output produced through the changed code still goes to a person for review before it is relied on or released, and is never merged or released automatically.
- [ ] 16. Governance and audit events the change touches are still recorded, and settings that block on error stay in place.
- [ ] 17. For a release: the AI test cases, including the human-approval cases, were run on this version and the results recorded (Annex A.6.2.4).

## Remarks (any No or N/A)

| # | Remark | Priority |
|---|---|---|
|   |   |   |
