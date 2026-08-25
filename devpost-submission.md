# Airlock — Devpost Submission Text
（Devpostの各欄にコピペ用。審査員は英語想定で英語。日本語版が要れば別途。）
Track: **Fortified Enterprise Fleet** · *Individual hackathon project. Not affiliated with or endorsed by Google or Anthropic.*

---

## Elevator pitch (one line)
Airlock turns your SOPs into least-privilege agents and governs the whole fleet at runtime. Dangerous tool calls are blocked **before they execute** — and proven with a **deterministic** scorecard. Ship agents fast; let none act unaudited.

## The problem
Teams can build an agent in an afternoon, but they can't *deploy* one. A single over-permissioned tool call — a $5,000 refund with no approval, a customer list emailed to an outside address — turns an "assistant" into an incident, and manual review can't keep pace. Airlock is the airlock every agent passes through before (and after) it reaches production.

## What it does
- **Generate (least privilege):** Paste a plain-language SOP. Gemini 3.5 emits an agent spec that selects *only* the tools the SOP needs, plus concrete guardrails, and registers it into the fleet.
- **Govern at runtime:** Every tool call runs through a Policy Engine via Google ADK callbacks. Dangerous actions — over-limit or redirected transfers, PII/secret exfiltration, unapproved irreversible operations — are **blocked before they execute**. A best-effort secondary layer flags injected instructions found in tool output; the primary, deterministic control is an allowlist + limit policy.
- **Prove it (deterministic where it counts):** An attack battery of fixed, pre-authored scenarios hits each agent. The verdict is decided by *instrumentation facts* — did a dangerous tool actually execute? — not by an LLM judge. A single `danger()` predicate is shared by both the policy (blocking) and the grader (breach), which makes **enforcement airtight: a blocked call can never execute, so with governance on, breaches are structurally zero.** (That is a guarantee about *enforcement*, not a claim that the predicate covers every threat — detection coverage is a separate, extensible axis; today it models four threat classes.)
- **Fleet & observability:** A scoreboard shows every agent, its least-privilege scope, and its posture. Every action, block, and reason is written to an audit trail; audit events publish to Pub/Sub.

**How this differs from prompt-level guardrails or LLM-judge evals:** Airlock enforces at the ADK *tool boundary* (not in a prompt) and grades on *execution facts* (not an LLM's opinion) — so "secure" is auditable, and the same predicate that blocks is the one that scores.

## How we built it
- **Gemini 3.5 Flash on Vertex AI** (global endpoint) — SOP→spec generation via structured output; the subject agents themselves run on Gemini 3.5. (Attack scenarios are fixed payloads authored by hand — not model-generated — so the battery is reproducible.)
- **Google ADK** — the agent runtime. `before_tool_callback` returns a substitute result to **skip** a dangerous tool (block); `after_tool_callback` inspects tool output for a best-effort injection flag.
- **Cloud Run** — API, server-rendered dashboard, audit runner. **Firestore** (named db) — registry, audit trail, scorecards. **Pub/Sub** — audit event stream.
- Deterministic grading: mock, instrumented "dangerous" tools; the ledger records only genuine executions, so blocked calls never count as breaches.

## Results (measured, honestly scoped)
- **Governance ON: zero breaches (structural).** No legitimate control operation in our battery was blocked. This verifies *enforcement*, not the completeness of the policy.
- **Governance OFF: real breaches occur** — e.g., an unapproved $5,000 refund executes, and a *synthetic* API key is POSTed to an external webhook. Whether a given attack lands depends on the model, so the OFF breach count **varies run to run** — that unpredictability is exactly the enterprise problem Airlock backstops. (The over-limit refund breaches every run; injection-style ones are intermittent.)
- **Marginal governance overhead ≈ 0.04 ms/call** (the before-tool danger check; the LLM latency is unchanged).
- **Least privilege by construction:** a support agent with no money tools cannot transfer funds at all; the false-positive control (a legitimate refund) still passes. Note: our regex rules (e.g., matching "card"/"password") could over-block legitimate messages containing those words — an untested boundary we call out rather than hide.

## Challenges we ran into
- **ADK fires `after_tool_callback` even when `before_tool_callback` blocked the call** (google-adk 2.7.1), which made blocked actions look like breaches. Fixed by detecting the block sentinel in the after-callback and not recording it as executed — covered by a regression test.
- **Frontier models refuse overtly malicious prompts on their own**, muddying "before/after." We reframed attacks as *plausible business operations that violate policy* (recipient redirection, PII-to-vendor export) so the model complies, the breach is real under OFF, and Airlock reliably catches it under ON.
- **Gemini 3.5 is served on Vertex's `global` endpoint**, not the region we first tried.

## What we learned
Runtime governance, not model choice, is the gate to enterprise agent deployment. And the most credible security demo isn't a table of 100%s — it's the same plausible operation breaching unguarded and being blocked under governance, with the (near-zero) cost measured and the limits stated.

## What's next
Real OS-sandboxed execution for untrusted agent code; a human-approval inbox for held actions; harder false-positive controls and boundary tests; org-wide policy packs; connectors to real tool backends behind the same interceptor; authenticated endpoints (the demo runs open for convenience).

## Built with
`google-adk` · `gemini-3.5-flash` · `vertex-ai` · `cloud-run` · `firestore` · `pub/sub` · `fastapi` · `python`

---

## 必須フィールド対応（要件のtext description）
- **Features/functionality:** "What it does"。
- **Technologies used:** "How we built it" / "Built with"。
- **Data sources:** 手作業で用意した固定の攻撃シナリオ＋計装モックツール（実データ・実送金なし、鍵は合成ダミー）。攻撃タクソノミーは公知のエージェント脅威（プロンプトインジェクション/ツール汚染/データ持ち出し/不可逆操作の無承認）。
- **Findings/learnings:** "Results" / "Challenges" / "What we learned"。
