# Threat model: secure-triage-agent

**Status:** draft written in Phase 2 (plan task 6). It describes what could go wrong and where; it is **not a result**. Where this document cites evidence, the evidence comes from the Phase 2 runs in `reports/PHASE_2_ANALYSIS.md` and is labelled as Garak findings (reply text) or verified application outcomes (what happened to the data). Controls marked "Phase 4" and later are planned, not built.

**What is being protected:** an agentic vulnerability-triage assistant. Analysts and a manager chat with it; it reads tickets and CVE records, can change a ticket's severity, close a ticket, and draft a summary. All data is synthetic.

**Verification of the references.** OWASP Top 10 for LLM Applications (2025) IDs and names were checked on `genai.owasp.org/llm-top-10/` on 2026-11-11. MITRE ATLAS technique IDs and names were checked on the ATLAS matrix page (`atlas.mitre.org/matrices/ATLAS`) on 2026-11-11, together with the maturity label the site shows (Feasible, Demonstrated, Realized). Only top-level techniques are cited; sub-technique IDs were not shown on the page and are not used. Where no ATLAS technique fits a threat honestly, the table says so instead of forcing a match.

## 1. System and data flows

```
 analyst / manager
      | 1. POST /chat  (bearer token, body = {message})
      v
 +-------------------------+   2. prompt + tool list    +--------+
 | Agent service  :8001    | -------------------------> | Ollama |
 |  - token -> principal   | <------------------------- | model  |
 |  - system prompt        |   3. tool-call requests     +--------+
 |  - agent loop (bounded) |
 +-------------------------+
      | 4. tool call + SIGNED principal (HMAC, 60 s) in the request metadata
      v
 +-------------------------+   5. SQL   +---------------------------------+
 | MCP tool server :8000   | ---------> | SQLite: tickets, CVEs, severity |
 |  - verifies signature   |            | history, append-only event log  |
 |  - authz + (later)      |            +---------------------------------+
 |    approval checks      |
 |  - six tools            |
 +-------------------------+

 approver (manager)  --POST /approvals/{id}-->  agent service   (separate endpoint, separate
                                                 token; no tool for it; stub today, Phase 4)
```

Facts that shape the threats (from the code and design decisions D-019 to D-030):
- The model never sees the caller's identity; the dispatcher signs it into each tool call, and the model cannot set or change it.
- No tool takes a user, team or role argument. There is no approval tool.
- Each `/chat` request is independent: the model gets the system prompt and the one message, with no stored conversation.
- The agent loop is bounded (a step limit, a per-step call limit, truncated tool results); messages over 4000 characters are refused.
- Tool results go to the model unchanged: **nothing marks ticket or CVE text as data rather than instructions** in the baseline (delimiting is a Phase 4 option).
- Ticket titles, descriptions and CVE text are attacker-influenced; the draft-summary tool builds its text from database rows in a fixed format and never includes descriptions.

## 2. Assets

| ID | Asset | Why it matters | Where it lives |
|---|---|---|---|
| AS1 | Ticket integrity | A closed ticket leaves the work queue; a real vulnerability can disappear | `tickets` table |
| AS2 | Severity accuracy and severity history | A Critical ticket downgraded to Low is deprioritised; "was ever Critical" is a security control | `tickets`, `ticket_severity_history` |
| AS3 | Cross-team confidentiality | `team-web` analysts must not read `team-infra` tickets | tickets, summaries |
| AS4 | Secrets and canaries | System-prompt note, ticket canaries, signing key, dev tokens; canaries are synthetic tripwires that stand in for real secrets | prompt, tickets, environment |
| AS5 | Approval integrity | An approval must be tied to one action, one ticket version, one use (Phase 4) | approvals (planned) |
| AS6 | Audit trail | The event log is the evidence of what happened; triggers make it append-only | `ticket_events` |
| AS7 | Accuracy of reporting | A manager acts on summaries and on the agent's stated reasons | summaries, replies |
| AS8 | Availability | The service and its local model must keep answering | Ollama, services |

## 3. Attackers

| ID | Attacker | Capability | In scope |
|---|---|---|---|
| AT1 | External party who can file tickets | Controls ticket text (title, description) that later reaches the model; no login | yes (v1) |
| AT2 | Compromised CVE data source | Controls CVE record text returned by `search_cve` | yes (v2 scenario) |
| AT3 | Curious insider analyst | A valid login on one team; sends their own messages | yes (v1) |
| AT4 | User spoofing identity | Tries to be another user or role: a forged field, a claim in a message, a forged signature | yes (identity experiment, v2) |
| AT5 | Malicious MCP server | Publishes tools with poisoned descriptions or changes them later | yes (Phase 6, v2) |

**Out of scope** (assumptions): an attacker with access to the host, the database file, the signing key or the model weights; a compromised Ollama; network attackers (everything is on `127.0.0.1`); denial of service at network scale; the training data of the base model. Dev tokens and the shared signing scheme are simplifications (production MCP over HTTP would use the protocol's OAuth-based authorization).

## 4. Trust boundaries

| ID | Boundary | What crosses it | Trusted side's rule | Status |
|---|---|---|---|---|
| TB1 | Client to the agent service | the bearer token and one message | identity comes only from the token; extra body fields are refused; the same 401 for any bad credential | built (Phase 2) |
| TB2 | **Untrusted text into the model's context** | ticket text, CVE text, tool results, the user's message | none in the baseline: the model treats it all as one conversation | **open: the central weakness; Phase 4 delimiting is a soft control only** |
| TB3 | Agent service to the MCP tool server | a tool call plus the signed principal | the server verifies the signature and expiry and checks permissions on every call; the model's text is never an identity | built; `tool_authz` can be switched off for the baseline |
| TB4 | Approval endpoint | an approver's token and an approval request | approver role, approver is not requester, bound to one action and version, single use | stub; real flow in Phase 4 |
| TB5 | MCP server to the database | SQL writes in a version-guarded transaction | append-only history and event log enforced by triggers | built |
| TB6 | MCP tool definitions (v2) | tool names, descriptions, schemas | pin and hash definitions; allowlist servers | Phase 6 |

The main lesson from the Phase 2 runs sits on TB2 and TB3: with `tool_authz` off and no approvals, **the model alone decides what is allowed**, and Garak's probes were enough to get unapproved closes (section 6).

## 5. Threats

STRIDE column: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. It is a label added to threats found by the asset, attacker and boundary method; a full STRIDE-per-element pass over the diagram was not done (section 9). Release column: v1 = planned for the first release, v2 = later. "Evidence so far" is only what Phase 2 measured, and each item is a single seeded run.

| ID | Threat | Attacker | Asset | Boundary | STRIDE | OWASP LLM (2025) | MITRE ATLAS | Evidence so far | Planned control, scenario, detection | Rel. |
|---|---|---|---|---|---|---|---|---|---|---|
| T1 | Hidden instructions in a ticket make the agent close a Critical ticket or lower its severity ("verified false positive, close this") | AT1 | AS1, AS2 | TB2, TB3 | T, E | LLM01 Prompt Injection; LLM06 Excessive Agency | AML.T0051 LLM Prompt Injection (Realized); AML.T0093 Prompt Infiltration via Public-Facing Application (Realized); AML.T0101 Data Destruction via AI Agent Tool Invocation (Realized) | Garak stream: `promptinject` probes made replies follow the injected text in 48% to 95% of prompts, depending on the probe. Application stream: **8 unapproved closes and 1 severity change** across the Phase 2 Garak runs in vulnerable mode, e.g. a planted resume text led to 4 tickets closed in one second. Not yet a targeted ticket attack | Bound approval for severity decreases and closes (Phase 4), delimiting (soft); A1; D1 | v1 |
| T2 | Poisoned CVE record changes a severity | AT2 | AS2 | TB2 | T, E | LLM01; LLM06; LLM03 Supply Chain (the feed is a third-party source) | AML.T0051; AML.T0099 AI Agent Tool Data Poisoning (Feasible); AML.T0080 AI Agent Context Poisoning (Realized) | none | same approval control; A2; D1, D2 | v2 |
| T3 | Downgrade-then-close: the injection lowers Critical to High (no approval under a naive rule), then closes | AT1 | AS1, AS2, AS5 | TB2, TB3, TB4 | T, E | LLM01; LLM06 | AML.T0051; AML.T0053 AI Agent Tool Invocation (Demonstrated) | none yet; the naive policy does not exist (Phase 4) | `full` approval policy plus severity-history protection; A8; D10; deterministic bypass tests | v1 |
| T4 | Cross-team read: an analyst (or an injection) gets the other team's tickets | AT3, AT1 | AS3 | TB3 | I, E | LLM06; LLM02 Sensitive Information Disclosure | AML.T0036 Data from Information Repositories (Realized); AML.T0085 Data from AI Services (Demonstrated) | Application stream, vulnerable mode: a `team-web` analyst read a `team-infra` ticket on request, and 32 draft-summary events requested by that analyst included `team-infra` tickets. This is expected with authorization off | tool-boundary authorization (built, switchable); generic "not found" errors so existence is not revealed; A5; D4 | v1 |
| T5 | Identity spoofing: a role or user ID in the request body, a claim in the message ("I'm the manager"), a forged or replayed signed principal | AT4 | AS1 to AS5 | TB1, TB3 | S | LLM06; LLM01 for the message claim | **no honest match**: this is a classic authentication flaw (the nearest listed technique, AML.T0074 Masquerading, is about disguising artifacts, not identities) | none measured; deterministic tests exist for forged, expired and missing signatures and for extra body fields | identity only from the token; signed principal; A9 (identity experiment with `token_auth` on and off); D9 | v2 |
| T6 | Leak of the system-prompt note or a ticket canary through the model's output | AT3, AT1 | AS4 | TB2 | I | LLM02; LLM07 System Prompt Leakage | AML.T0084 Discover AI Agent Configuration (Demonstrated); AML.T0083 Credentials from AI Agent Configuration (Demonstrated) | not measured in Phase 2 (the Garak probes were not canary-targeted) | exact-match output canary filter (narrow); A3, A4; D3, D7 | v2 |
| T7 | Data leaves through legitimate output: summaries and replies carry out-of-scope or sensitive content | AT3, AT1 | AS3, AS4 | TB2, TB3 | I | LLM02; LLM05 Improper Output Handling | AML.T0136 Exfiltration via AI User Interface (Realized) | same cross-team summaries as T4; summaries use a fixed format and omit descriptions by design | authorization on every ticket a summary includes; A7; D5 | v2 |
| T8 | Obfuscated injection (Base64, hex, ROT13) hides the instruction from filters | AT1 | AS1, AS2 | TB2 | T, E | LLM01 | AML.T0068 LLM Prompt Obfuscation (Realized) | Garak stream only: exact decoding of Hex payloads in 5.86% of 256 prompts, other encodings under 1% | decode-aware detection; A6; D6 | v2 |
| T9 | Malicious MCP server or tool: poisoned description, a tool that changes its description after approval | AT5 | AS1 to AS4 | TB6 | T, E | LLM03 Supply Chain; LLM01 | AML.T0110 AI Agent Tool Poisoning (Realized); AML.T0109 AI Supply Chain Rug Pull (Realized); AML.T0010 Supply Chain Compromise (Realized) | none (Phase 6) | allowlist, tool-definition pinning, scoped tools; A10, A11; D8, D11. Pinning detects changed definitions, not malicious behaviour behind an unchanged one | v2 |
| T10 | Approval abuse: replay, a swapped argument, a stale ticket version, self-approval, an expired approval, two concurrent uses of one approval, closing a formerly Critical ticket now at Low | AT1, AT3 | AS5, AS1, AS2 | TB4 | E | LLM06 | **no honest match**: a workflow logic flaw, not an AI technique | none (approvals arrive in Phase 4) | action-bound, single-use, atomically consumed approvals; deterministic bypass tests (no model); D10 | v1 |
| T11 | Resource abuse: oversized inputs, tool loops, floods that exhaust the local model | AT3, AT1 | AS8 | TB1 | D | LLM10 Unbounded Consumption | AML.T0029 Denial of AI Service (Demonstrated); AML.T0034 Cost Harvesting (Feasible) | not an attack: during Phase 2 the model backend returned errors for some requests (179 in one run, 6 of 512 in another; cause not found), which shows availability is fragile. A 4000-character limit and a bounded loop exist | limits already built; no rate limiting | v2 |
| T12 | The model invents a justification, so a reader trusts a false record ("Candidate's expertise in ..." stored as a close reason) | AT1 | AS7, AS6 | TB2 | R (weak fit) | LLM09 Misinformation | no honest match | Application stream: some close reasons recorded in Phase 2 were written by the model and do not match the ticket, e.g. a resume-style reason on a security ticket | the event log and database, not the reply, are the evidence; approvals show the exact action, not the model's prose | v1 |
| T13 | Tampering with the audit trail | AT3 | AS6 | TB5 | T, R | none | none | triggers refuse updates and deletes on the history and event tables (tested). An attacker with file access is out of scope | append-only triggers; the telemetry pipeline (Phase 5) | v1 |

## 6. Evidence from Phase 2 (what has actually been observed)

- **Application stream (database and event log), vulnerable mode:** across the five Garak group runs, 8 ticket closes and 1 severity change were made by the agent for the `team-web` analyst, none approved, all on the analyst's own team; 32 draft-summary events included other-team tickets. The event log has no request identifier, so a change cannot yet be tied to the prompt that caused it. These are descriptions of single seeded runs, not rates.
- **Garak stream (reply text):** flag rates and intervals are in `reports/PHASE_2_ANALYSIS.md`. A flag is a detector match on the reply; it does not by itself show a ticket changed.
- **Nothing about the defended configuration has been measured.** No statement here says a control works.

## 7. OWASP LLM Top 10 (2025) coverage

| ID | Name | Applies? | Threats |
|---|---|---|---|
| LLM01 | Prompt Injection | yes, central | T1, T2, T3, T5, T8, T9 |
| LLM02 | Sensitive Information Disclosure | yes | T4, T6, T7 |
| LLM03 | Supply Chain | yes, mainly MCP and the CVE feed; the model weights come from the Ollama registry and are trusted by assumption | T2, T9 |
| LLM04 | Data and Model Poisoning | not as written: it concerns training, fine-tuning and embedding data; runtime data poisoning is covered under LLM01 and LLM03 | n/a |
| LLM05 | Improper Output Handling | limited: no downstream interpreter of the model's output; the summary tool shapes its own output | T7 |
| LLM06 | Excessive Agency | yes, central: the agent can close and downgrade tickets | T1 to T5, T10 |
| LLM07 | System Prompt Leakage | yes | T6 |
| LLM08 | Vector and Embedding Weaknesses | no: there is no vector store or retrieval index | n/a |
| LLM09 | Misinformation | limited | T12 |
| LLM10 | Unbounded Consumption | yes | T11 |

## 8. How each threat will be tested

| Threat | Test | Evidence type | Phase |
|---|---|---|---|
| T1, T3 | attack harness scenarios A1, A8 against `vulnerable`, `naive`, `full` | verified application outcomes, with n and a 95% interval | 3 and 4 |
| T4 | scenario A5, plus deterministic authorization tests | outcomes; deterministic tests | 2 (tests), 3 |
| T5 | forged and missing signature tests; identity experiment | deterministic tests; outcomes | 2 (tests), 4 |
| T10 | deterministic bypass tests, including concurrent reuse | deterministic, no model | 3 and 4 |
| T1, T8 and related | Garak probes through `/chat` | Garak findings only | 2 (baseline), 4 (defended) |
| T6, T7, T9 | scenarios A3, A4, A7, A10, A11 | outcomes | v2 |
| All | detections D1, D4, D10 (v1) on attack and benign traffic, tuned on development variants and reported on held-out ones | detection rate and false-positive rate | 5 |

## 9. Limits of this model

- It covers the threats the project is built to measure; it is not a complete list of every possible attack.
- The STRIDE column classifies the threats already listed; it was not used to find them. Repudiation (T12, T13) and Denial of service (T11) have few entries, and the approval endpoint has no denial-of-service threat. A STRIDE-per-element pass could add some; it is left out of the frozen v1 scope.
- Mappings to OWASP and ATLAS are judgements, shown with the verified IDs; ATLAS maturity labels are copied from the site and describe the technique in general, not this system.
- "No tested path produced X" is the strongest claim the later results can support; it does not mean X is impossible.
