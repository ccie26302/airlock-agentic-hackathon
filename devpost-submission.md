# Airlock — Devpost submission text
Track: **Fortified Enterprise Fleet** · *Individual project. Not affiliated with or endorsed by Google.*

**Demo video:** https://youtu.be/3LaorTM5pgw  (live, unedited, English captions)
The video is one continuous take of the deployed system. Two things landed after it was recorded and
are visible live rather than on film: the Gemma fleet member (`/fleet` now lists five departments,
the video shows four) and the duplicate-settlement check. Nothing in the video was superseded —
except one on-screen label that read "gVisor", which is the gen1 execution environment; this runs
gen2 and Google does not state the isolation used by `--sandbox-launcher`, so the label now says
`--sandbox-launcher · egress blocked`. The measured result it sits next to is unchanged.
**Repository:** https://github.com/ccie26302/airlock-agentic-hackathon
**Live:** https://airlock-52kgcfrghq-uc.a.run.app/mission?lang=en

---

## Bonus / content contributions

- **Article (public, states it was written for this hackathon):**
  https://zenn.dev/acntechjp/articles/zenn-airlock-agent-governance
  Covers how the project was built, including the measurements that changed the design.
- **Social post (LinkedIn, tagged #AllThingsAgenticHackathon):** https://lnkd.in/p/gXFGj2vC
- **Additional Google AI models integrated:**
  - **Gemma 3 (4B)** on an NVIDIA L4 — a fleet member with the same tools, instruction and callbacks
    as an existing agent, so that enforcement can be shown to hold for a model that is not Gemini.
    It failed the CI gate and was refused production data; 5 items in, 5 quarantined.
  - **`gemini-embedding-001`** — duplicate-settlement detection. The threshold (0.96) was measured
    against real complaints before the feature was written; the first measurement said the naive
    version would not work. Caught 5 settled disputes on a re-run with no false positives.

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
  Measured: **200 items in 60 seconds, 0 failed, 0 human interventions during the run** —
  193 completed, 5 escalated to a human, 2 blocked. What is handed to a person is handed on purpose:
  the number worth reporting is not how few humans it needs but where it decides it needs one.
- **Scores its own agents against reality.** CFPB records what each company actually did about each
  complaint. The agents decide the same thing without ever seeing that answer, so the decision is
  checkable: **94% recall, 41% precision — and 50% raw agreement against a 65% baseline you would get
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

## The duplicate the ledger could not see
The ledger makes redelivery safe — the same item is never paid twice — but says nothing about two
different complaints that are the same dispute. A second Google model, `gemini-embedding-001`, now
compares each complaint against the disputes already settled.

The threshold was measured first, and the first measurement said no: across real complaints, unrelated
pairs reach 0.946 while same-company/same-issue pairs top out at 0.910 — the distributions overlap, so
"similar" does not mean "the same dispute". What does separate is the case the control is for: a
refiling scores 0.974–1.000. The threshold sits at 0.96, in that gap, and a match escalates to a human
rather than blocking. Measured: the same 40 items run twice, and the second run caught 5 settled
disputes at 1.000 with no false positives among the other 33.

## A second model, and the bug it exposed
Enforcement sits in the tool callback, below the model — so it should hold for a model that is not
Gemini. The fleet now includes `gemma_intake_agent`: **Gemma 3 (4B) on an NVIDIA L4**, with the same
instruction, tools and callbacks as an existing agent. Only the model differs.

It failed the CI gate — one false positive, and zero unsafe actions reached even with governance off,
so its clean sheet proves the model's limits rather than the platform's. Work sent to it was refused:
5 items in, 5 quarantined, 0 processed.

Adding it also exposed a real hole: CI passes were fingerprinted over instruction and tools but **not
the model**, so swapping Gemini for Gemma would have kept the old pass valid. Changing the model is
the change most in need of re-verification. It is in the fingerprint now, and every agent went stale
and had to re-prove itself.

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
