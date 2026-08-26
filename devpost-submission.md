# Airlock — Devpost Submission Text
（Devpostの各欄にコピペ用。英語。）
Track: **Fortified Enterprise Fleet** · *Individual hackathon project. Not affiliated with or endorsed by Google or Anthropic.*

---

## Elevator pitch
Airlock turns your SOPs into least-privilege agents that do real work on Google Cloud, and wraps them in **three layers of defense** — language, action, and execution. Overt injections, plausible-but-forbidden actions, and even hijacked code execution are all contained, and proven with a **deterministic** scorecard. Ship agents fast; let none act unaudited.

## The problem
Teams can build an agent in an afternoon, but they can't *deploy* one. One over-permissioned tool call — a $5,000 refund with no approval, a customer list emailed outside, or generated code that quietly reads the VM's service-account token — turns an "assistant" into an incident. No single guard stops all three. Airlock is the platform that makes an agent safe enough to ship.

## What it does
- **Generate (least privilege):** Paste a plain-language SOP. Gemini 3.5 emits an agent spec that selects *only* the tools the SOP needs, and registers it into the fleet.
- **Run real work:** Agents complete real operations on Google Cloud — read orders/customers from **Firestore**, write to a real refunds ledger and email outbox, make real outbound HTTP calls, and run analysis code. (Only the payment gateway is simulated — no real funds move.)
- **Defend in three layers (each catches what the others can't):**
  - **L1 — language:** **Google Model Armor** screens every incoming prompt and blocks prompt injection / jailbreak before the agent runs.
  - **L2 — action:** a deterministic Policy Engine inspects every tool call via Google ADK callbacks and **blocks dangerous actions before they execute** (over-limit/redirected transfers, PII/secret exfiltration, unapproved irreversible ops).
  - **L3 — execution:** agent-run code executes inside a **Cloud Run sandbox** (gVisor). Even a hijacked code path can't reach the metadata server or the network — it physically cannot steal the service-account token.
- **Prove it deterministically:** an attack battery grades on *instrumentation facts* (did a dangerous tool actually execute?), not an LLM judge. One `danger()` predicate is shared by the policy and the grader, so with governance on, breaches are **structurally zero** — a guarantee about enforcement (a blocked call can never execute), not a claim the predicate covers every threat.
- **Fleet & observability:** a bilingual (JA/EN) dashboard shows each agent's least-privilege scope and posture, every block and its reason (which layer caught it), an audit trail in Firestore + Cloud Logging, and audit events on Pub/Sub.

**How this differs from prompt-level guardrails or LLM-judge evals:** Airlock enforces at the ADK tool boundary and at the OS/execution boundary, and grades on execution facts — so "secure" is auditable across all three layers, not a prompt-level suggestion.

## Key results (measured, honestly scoped)
- **Governance ON: zero breaches (structural), zero legit ops blocked.** Attacks are caught across layers — overt injections by Model Armor, plausible-but-forbidden actions by the policy engine.
- **Layer 3, verified live and LLM-independently:** the *same* service-account-token-theft code **leaks the real token when run directly**, but is **contained inside the Cloud Run sandbox** (network unreachable). This is the article-verified property, reproduced inside Airlock and shown on the dashboard.
- **Governance OFF: real breaches occur** — e.g., an unapproved $5,000 refund executes and a synthetic API key is POSTed to an external endpoint. Whether a given attack *lands* depends on the model, so the OFF count varies run to run — that unpredictability is exactly the enterprise problem Airlock backstops. (The over-limit refund breaches every run.)
- **L2 policy-check ≈ 0.04 ms/call** (the before-tool predicate only — this number *excludes* Model Armor's network round-trip and the sandbox spawn cost, which are separate; we call that out rather than present a one-sided figure).

## How we built it
- **Gemini 3.5 Flash on Vertex AI** (global) — SOP→spec generation (structured output); the agents run on Gemini too. Attack scenarios are fixed, hand-authored payloads (not model-generated) for reproducibility.
- **Google ADK** — `before_tool_callback` returns a substitute result to block a dangerous tool; `after_tool_callback` inspects tool output.
- **Model Armor** — `sanitizeUserPrompt` with a PI/jailbreak + malicious-URI template.
- **Cloud Run** (gen2, `--sandbox-launcher`) — API, dashboard, and `sandbox do` isolated code execution. **Firestore** (named db) — registry, real business data, audit, scorecards. **Pub/Sub** — audit events.

## Challenges we ran into
- **ADK fires `after_tool_callback` even when `before_tool_callback` blocked** (v2.7.1) — blocked calls looked like breaches until we detected the block sentinel; covered by a regression test.
- **Frontier models refuse overtly malicious prompts on their own**, so we reframed action-layer attacks as *plausible business operations that violate policy*, and proved the sandbox layer with a fixed probe rather than relying on the model to write malicious code.
- **Cloud Run sandbox has an empty PATH** — commands need full paths (`/bin/sh`, `/usr/local/bin/python3`); code is carried in as base64 to survive the sandbox command parser.

## What we learned
Runtime governance across language, action, and execution — not model choice — is the gate to enterprise agent deployment. The most credible security demo isn't a table of 100%s; it's the same operation breaching unguarded and being contained under governance, with the (near-zero) cost measured and the limits stated.

## What's next
Human-approval inbox for held actions; harder false-positive/boundary tests; org-wide policy packs; connectors to real tool backends behind the same interceptors; authenticated endpoints (the demo runs open for convenience).

## Built with
`google-adk` · `gemini-3.5-flash` · `vertex-ai` · `model-armor` · `cloud-run` (sandbox) · `firestore` · `pub/sub` · `fastapi` · `python`

---

## 必須フィールド対応
- **Features:** "What it does"。 **Technologies:** "How we built it" / "Built with"。
- **Data sources:** 実Firestoreの合成業務データ(顧客/注文)＋手作業の固定攻撃シナリオ＋計装。実送金なし、鍵は合成ダミー。
- **Findings/learnings:** "Key results" / "Challenges" / "What we learned"。
