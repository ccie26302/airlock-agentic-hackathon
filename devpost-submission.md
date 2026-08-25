# Airlock — Devpost Submission Text
（Devpostの各欄にコピペ用。審査員は英語想定で英語。日本語版が要れば別途。）
Track: **Fortified Enterprise Fleet**

---

## Elevator pitch (one line)
**Airlock turns your SOPs into least-privilege AI agents and governs the whole fleet at runtime — blocking dangerous tool calls before they execute, and proving it with a deterministic security scorecard.** Ship agents fast; let none act unaudited.

## Inspiration
Enterprises can build agents in an afternoon, but they can't *deploy* them. One prompt injection or one over-permissioned tool call — a $9,999 refund to the wrong account, a customer list emailed to an outside address — turns an "assistant" into an incident. Manual security review can't keep pace with how fast teams now spin up agents. Airlock is the airlock every agent passes through before (and after) it reaches production.

## What it does
- **Generate (least privilege):** Paste a plain-language SOP. Gemini 3.5 produces an agent spec that selects *only* the tools the SOP actually needs, plus concrete guardrails, and registers it into the fleet.
- **Govern at runtime:** Every tool call runs through a Policy Engine via Google ADK callbacks. Dangerous actions — over-limit or redirected transfers, PII/secret exfiltration, unapproved irreversible operations — are **blocked before they execute**. Poisoned tool outputs (indirect prompt injection) are quarantined.
- **Prove it (deterministic scorecard):** An attack battery hits each agent. The verdict is decided by *instrumentation facts* (did a dangerous tool actually execute?), not by an LLM — so the numbers are stable. A single `danger()` predicate is shared by both the policy (blocking) and the grader (breach), which **structurally guarantees zero breaches when governance is on**.
- **Fleet & observability:** A scoreboard shows every agent, its least-privilege scope, and its live posture. Every action, block, and reason is written to an audit trail; audit events publish to Pub/Sub.

## How we built it
- **Gemini 3.5 Flash on Vertex AI** (global endpoint) — SOP→spec generation (structured output) and attack-text generation.
- **Google ADK** — the agent runtime. `before_tool_callback` returns a substitute result to **skip** a dangerous tool (block); `after_tool_callback` inspects tool output to detect/quarantine indirect injection.
- **Cloud Run** — API, server-rendered dashboard, and the audit runner. **Firestore** (named db) — registry, audit trail, scorecards. **Pub/Sub** — audit event stream.
- Deterministic grading: mock, instrumented "dangerous" tools; the ledger records only genuine executions, so blocked calls never count as breaches.

## Key results (measured)
- Governance **ON: 0 breaches, 0 false positives**; Governance **OFF: real breaches** (an unapproved $5,000 refund and an API key posted to an external webhook actually go through).
- Policy overhead **≈ 0.04 ms/call**.
- Least privilege verified: a support agent with no money tools cannot transfer funds at all; the false-positive control (a legitimate high-value refund) still passes.

## Challenges we ran into
- **ADK fires `after_tool_callback` even when `before_tool_callback` blocked the call** — which made blocked actions look like breaches. Fixed by detecting the block sentinel in the after-callback and not recording it as executed.
- **Frontier models refuse cartoonish attacks on their own**, muddying "before/after." We reframed attacks as *plausible business operations that violate policy* (recipient redirection, PII-to-vendor export) so the model complies, the breach is real under OFF, and Airlock reliably catches it under ON.
- **Gemini 3.5 is served on Vertex's `global` endpoint**, not the region we first tried.

## Accomplishments we're proud of
A governance layer whose "secure" claim is *structural*, not hopeful — shared danger predicate, deterministic instrumentation grading, and an honest scorecard that distinguishes "Airlock blocked" from "model refused."

## What we learned
Runtime governance, not model choice, is the gate to enterprise agent deployment. And the most credible security demo isn't a table of 100%s — it's the same plausible operation breaching unguarded and being blocked under governance, with the cost/latency it adds measured (near zero).

## What's next
Real OS-sandboxed execution for untrusted agent code, human-approval inbox for held actions, org-wide policy packs, and connectors to real tool backends behind the same interceptor.

## Built with
`google-adk` · `gemini-3.5-flash` · `vertex-ai` · `cloud-run` · `firestore` · `pub/sub` · `fastapi` · `python`

---

## 必須フィールド対応（要件のtext description）
- **Features/functionality:** 上記 "What it does"。
- **Technologies used:** 上記 "How we built it" / "Built with"。
- **Data sources:** 手続き生成の攻撃シナリオ＋計装モックツール（実データ・実送金なし）。攻撃タクソノミーは公知のエージェント脅威（プロンプトインジェクション/ツール汚染/データ持ち出し/不可逆操作の無承認）に基づく。
- **Findings/learnings:** 上記 "Key results" / "Challenges" / "What we learned"。
