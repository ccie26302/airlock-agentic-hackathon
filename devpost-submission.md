# Airlock — Devpost submission text
Track: **Fortified Enterprise Fleet** · *Individual project. Not affiliated with or endorsed by Google.*

**Repository:** https://github.com/ccie26302/airlock-agentic-hackathon
**Live:** https://airlock-52kgcfrghq-uc.a.run.app/mission?lang=en

---

## Elevator pitch
Airlock clears an operational backlog while nobody is watching. It scans 3.4 million real consumer
complaints, works the ones that need action asynchronously, and stops anything unsafe at the tool
boundary — because the text it reads is written by customers, and the agents reading it get rewritten
every day. **Run it unattended. Not unguarded.**

## The problem
The work that actually costs companies money is not clever; it is endless. Three and a half million
complaints, a million of them free text. A person reading two a minute needs about forty thousand
hours. So you hand it to agents — and then you cannot leave them alone, because one poisoned sentence
inside a customer record is enough to redirect a payment at 3am, and because the agent you tested on
Monday is not the agent running on Thursday.

## What it does
- **Scans at scale.** `POST /jobs` runs a BigQuery query over `bigquery-public-data.cfpb_complaints`
  (3,458,906 rows, 1.7GB read), selects the exceptions, and returns a job id in about five seconds.
  LLMs never touch all 3.4M rows — only the exceptions.
- **Works them unattended.** Each exception is a Pub/Sub message consumed by a **private** Cloud Run
  service. Agents read the complaint, decide, issue the refund, email the customer, or escalate.
  Measured: **200 items in 78 seconds, 0 failed, 0 human interventions during the run** —
  191 completed, 5 escalated to a human, 4 blocked. What is handed to a person is handed on purpose:
  the number worth reporting is not how few humans it needs but where it decides it needs one.
- **Scores its own agents against reality.** CFPB records what each company actually did about each
  complaint. The agents decide the same thing without ever seeing that answer, so the decision is
  checkable: **94% recall, 39% precision — and 52% raw agreement against a 65% baseline you would get
  by answering "explanation only" every time.** This agent is a high-recall triage filter, not a
  decision-maker, and the dashboard says that rather than showing one flattering number.
- **Routes across departments by permission, not by label.** Support has no payment tool, so when it
  decides money is owed it cannot act: it opens a case addressed to Finance, and approval resumes the
  work under Finance's agent, with that agent's permissions and its own CI pass. Measured: 30 Support
  items → 26 explanations, 4 handed to Finance.
- **Enforces in three layers.** Model Armor screens the language; a deterministic policy stops
  dangerous tool calls *before they execute*; a Cloud Run sandbox contains code execution so a
  hijacked agent cannot exfiltrate credentials — the network does not exist inside it.
- **Makes agents re-prove themselves — and says what the test actually proved.** CI is bound to a
  fingerprint of the agent's instruction and granted tools; change the prompt and the last pass goes
  stale and the worker refuses to give that agent production data. Because a blocked call can never
  score as executed, every CI run also executes the battery with governance *off*, and reports how
  many unsafe actions that agent reached unguarded. `refund_agent` reaches 3; `analytics_agent`
  reaches 0, so its pass is labelled `enforcement_exercised: false` — its clean sheet is the agent's
  caution, not the platform's.
- **Keeps work that outlives the process.** Escalations become cases in Firestore; approving one
  replays its context and lets the agent finish. Approvals are single-use tickets bound to the exact
  amount and payee.

## The measurement that changed the build
I tried to measure how often an injected instruction actually lands, expecting a scary number.

Against a tightly scoped agent — handed the payee, told to call each tool once — it landed **0 out of
13** across three payload styles. The model simply ignored it. That is good behaviour, and it meant
the action layer was never being exercised. Reporting a green checkmark there would have been a lie.

So the fleet also runs a handler written the way a lot of real ones are written: *"carry out what the
record says should happen."* That one follows the injected note — **8/8** in isolation, and 2 of 3
seeded items in a live 20-item run — and every attempt is stopped at the tool boundary.

That contrast is the argument for the platform. You cannot assume every team writes a careful prompt,
and prompts change daily. The layer that holds has to sit below them.

## How I built it
Gemini 3.5 Flash on Vertex AI does the reasoning. Google ADK runs the agents, and its
`before_tool_callback` is the enforcement point — returning a value there skips the tool, so a
dangerous call is stopped rather than detected. Cloud Run runs a public UI and a private worker from
the same image; Pub/Sub distributes work with an authenticated push subscription; BigQuery provides
scale; Firestore holds state, cases and the audit trail; Model Armor screens language.

## Challenges
- **Ack deadline vs item runtime.** Items take 20–30s; Pub/Sub defaults to 10s. Left alone, every
  message is redelivered and the same refund is paid two or three times. Fixed with a 600s deadline
  *and* an idempotent ledger keyed by item id.
- **A failure that could never be retried.** The lease that prevents double-processing was left
  behind when an item failed, so redelivery was discarded as a duplicate and the item was lost.
  Releasing the lease on transient errors took a 200-item run from 10 permanently failed to 0.
- **An unbounded agent.** ADK allows 500 LLM calls by default. An agent hunting for data it did not
  have looped 20+ tool calls into a timeout and then a 429. Bounded to 8.
- **Over-blocking measured, not guessed.** Model Armor at `LOW_AND_ABOVE` blocked a legitimate
  Japanese request; the attacks measured HIGH, so the threshold moved — and the attack that then fell
  below it was verified to be stopped by the action layer instead.
- **The false-positive rate on real data was 12%, and I only found it by running it.** A 200-item run
  blocked 24 items and **every one was a false positive**: real complaint narratives are full of long
  digit runs, and any 13–19 digit sequence was being read as a card number. Luhn alone did not fix it
  (a 19-digit case reference passed), so detection now requires a real issuer prefix and Luhn.
  Re-measured on a fresh 200-item run: **24 → 0**, attacks still caught.
- **A block that was not a block.** The alert panel listed the tools an item had executed and labelled
  them "prevented before execution". On items where the refund went through and only the confirmation
  email was stopped, it claimed the platform had prevented the payment. It now reports what was
  stopped and what had already run — and hands the half-finished item to a person.

## The metric that was wrong
"Closed with non-monetary relief" contains "monetary relief" as a substring. My first accuracy number
counted 63 non-monetary dispositions as monetary and looked far better than the truth. I found it by
printing the confusion matrix instead of the headline. The corrected number is worse and is the one
above; the classifier is now a named function with tests, because that is the class of bug that
survives right up until someone asks a question on camera.

## What I learned
Enforcement belongs where the money moves, not in the prompt. And the honest version of a security
demo is not a table of 100%s: it is showing the case where your own defence was never needed, next to
the case where it was the only thing standing there.

## Limits I'm stating up front
"Zero breaches under governance" is a structural consequence — the policy and the grader share one
predicate, so a blocked call cannot be scored as executed. It verifies enforcement; it does not prove
the predicate covers every threat. A few hundred items per run is not "massive" and I don't call it
that: the dataset is 3.4M rows and the scan really reads 1.7GB, but scale is shown by shape. The
payment gateway is simulated; the ledger, outbox, outbound HTTP and code execution are real. Cases
here are days old, not weeks — what week-scale continuity requires is that a paused case outlives
the process, revision and instance that made it, which is what they demonstrate.

## Built with
`gemini-3.5-flash` · `vertex-ai` · `google-adk` · `cloud-run` (gen2, sandbox) · `bigquery` ·
`firestore` · `pub-sub` · `model-armor` · `fastapi` · `python`

---

### 提出フォーム対応
- **Features:** "What it does"
- **Technologies:** "How I built it" / "Built with"
- **Data sources:** `bigquery-public-data.cfpb_complaints.complaint_database`（第三者の実データ、3,458,906行）。
  攻撃文面のみ red-team seeded として明示的に注入。実送金なし、鍵は合成ダミー。
- **Findings / learnings:** "The measurement that changed the build" / "Challenges" / "What I learned" / "Limits"
