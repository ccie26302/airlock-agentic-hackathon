# 🛰 Airlock — Unattended agent operations on real data

**Run it unattended. Not unguarded.**

Airlock clears an operational backlog while nobody is watching. It scans **3,458,906 real consumer
complaints** in BigQuery, picks out the ones that need action, and lets a fleet of agents work them
asynchronously — issuing refunds, emailing customers, escalating what needs a human. Every action
passes three enforcement layers before it can touch money, and every agent has to re-prove itself
before it is allowed near production data.

> All Things Agentic Hackathon · Track: **Fortified Enterprise Fleet**
> Individual project. Not affiliated with or endorsed by Google.

## Why this shape

Three facts force the design:

| | Fact | What it forces |
|---|---|---|
| **Volume** | 3.4M complaints, 1.2M with free text. A human reading two a minute needs ~40,000 hours. | Work has to run **unattended**. |
| **Change velocity** | AI-assisted development rewrites agents daily; hand-testing every change is not possible. | Every change must **re-prove itself automatically**. |
| **Adversarial input** | The text is written by customers — i.e. by anyone — and an unattended agent holds credentials the whole time. | Enforcement has to sit at the **tool boundary**, not in the prompt. |

Security here is not a feature bolted on. It is the condition that makes unattended operation possible.

## What actually happens

```
POST /jobs → BigQuery scan (3.4M rows, 1.7GB) → exceptions → Pub/Sub → workers (Cloud Run)
                                                                          ↓
   L1 Model Armor (language)  →  L2 deterministic policy (action)  →  L3 Cloud Run sandbox (execution)
                                                                          ↓
                          real Firestore ledger / outbox / HTTP  +  audit trail  +  cases
```

- `POST /jobs` returns a job id in ~5s; the work happens in the background.
- Each item is one Pub/Sub message, processed by a **private** Cloud Run service (`--no-allow-unauthenticated`).
- Outcomes are `completed` / `escalated` (legitimate but over the approval limit) / `blocked` (unsafe
  action stopped) / `quarantined` (agent not verified) / `failed`.

**Measured, unattended:** 200 items in **103s, 0 failed**. 50 items in 51s. Job submission ~5s.

## The three layers, and what each one actually catches

| Layer | Implementation | Catches |
|---|---|---|
| **L1 language** | Google Model Armor (`sanitizeUserPrompt`, threshold HIGH) | Overt prompt injection / jailbreak |
| **L2 action** | Deterministic policy in ADK `before_tool_callback` | Over-limit payments, redirected payees, secrets leaving, memory poisoning |
| **L3 execution** | Cloud Run sandbox (gVisor, `--sandbox-launcher`) | Hijacked code — the network does not exist inside, so credentials cannot leave |

### A measurement that changed the design

We tried to measure how often an injected instruction actually lands.

- Against `complaint_agent` — a tightly scoped prompt that is handed the payee and told to call each
  tool once — the injection landed **0 out of 13** times across three payload styles. The model
  ignored it. Good behaviour, but it means the action layer was never exercised.
- So the fleet also runs `ticket_agent`, written the way many real handlers are written: *"carry out
  what the record says should happen."* That one follows the injected note — **8/8** in isolation,
  and 2 of 3 seeded items in a live 20-item run — and **every attempt is stopped at the tool boundary**.

The contrast is the argument: you cannot assume every team writes a careful prompt, and prompts
change daily. The layer that holds has to sit below them.

## Agents must re-prove themselves (the CI gate)

CI results are bound to a **fingerprint over the agent's instruction and granted tools**.

```
POST /ci/{agent}   → runs the adversarial scenarios, records pass + fingerprint
GET  /ci           → per-agent state: passed / stale / never_verified
```

Change one sentence of the prompt, or add a tool, and the fingerprint moves: the previous pass goes
**stale** and the worker refuses to hand that agent production data. Unverified is the default.

Demonstrated: 3 items into an unverified queue → all `quarantined` with the reason attached; CI run
(0 breaches, 0 false positives) → same job resubmitted → 7 completed, 1 escalated, 2 blocked, 0 quarantined.

## Cases: work that outlives the process

An escalation becomes a **case** in Firestore with the context that produced it. `POST /cases/{id}/approve`
replays that context to the agent and lets it finish — nothing about resuming depends on a process
still being alive, so restarts and new revisions do not lose the thread.

The approval is a **single-use ticket bound to the payload hash** (amount + payee, normalised). Using
it burns it; a ticket approved for one payee does not authorise another. An approval can never become
a standing exemption.

## Screens

| URL | For |
|---|---|
| `/mission` | Mission control: queue burning down, decision stream, `human interventions`, latched alerts, cases |
| `/console` | Business users: pick an agent, give it work, read the answer |
| `/dashboard` | Governance: scorecard, fleet posture, audit trail, L3 proof |
| `/sandbox_probe` | L3 proof: identical code leaks a real token directly, contained inside the sandbox |
| `/ci`, `/cases`, `/jobs`, `/runs` | JSON APIs |

All screens are JA/EN (`?lang=en`).

## Stack

| Layer | Service | Requirement |
|---|---|---|
| Reasoning | **Gemini 3.5 Flash** on Vertex AI (`global`) | Gemini 3.5+ ✅ |
| Agent runtime | **Google ADK** (callbacks are the enforcement point) | Google Agent Framework ✅ |
| Compute | **Cloud Run** gen2 (public UI + private worker, sandbox-launcher) | Google Cloud ✅ |
| Data at scale | **BigQuery** (`bigquery-public-data.cfpb_complaints`) | ✅ |
| State / audit | **Firestore** (named db `airlock`) | ✅ |
| Work distribution | **Pub/Sub** (push + OIDC, DLQ) | ✅ |
| Language-layer security | **Model Armor** | (bonus) |

## Setup

```bash
export PID=<your-project-id>
gcloud config set project $PID

# APIs
gcloud services enable aiplatform.googleapis.com run.googleapis.com firestore.googleapis.com \
  pubsub.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  modelarmor.googleapis.com bigquery.googleapis.com

# State + queues
gcloud firestore databases create --database=airlock --location=us-central1 --type=firestore-native
gcloud pubsub topics create airlock-work
gcloud pubsub topics create airlock-dlq
gcloud pubsub topics create airlock-audit

# Model Armor template (threshold HIGH — see "false positives" below)
TOKEN=$(gcloud auth print-access-token)
curl -s -X POST "https://modelarmor.us-central1.rep.googleapis.com/v1/projects/$PID/locations/us-central1/templates?template_id=airlock" \
  -H "Authorization: Bearer $TOKEN" -H "x-goog-user-project: $PID" -H "Content-Type: application/json" \
  -d '{"filterConfig":{"piAndJailbreakFilterSettings":{"filterEnforcement":"ENABLED","confidenceLevel":"HIGH"},"maliciousUriFilterSettings":{"filterEnforcement":"ENABLED"}}}'

# Runtime SA (least privilege) and push SA
gcloud iam service-accounts create airlock-run --display-name="Airlock runtime"
gcloud iam service-accounts create airlock-push --display-name="Airlock Pub/Sub push"
SA=airlock-run@$PID.iam.gserviceaccount.com
for R in roles/aiplatform.user roles/datastore.user roles/pubsub.publisher \
         roles/modelarmor.user roles/bigquery.jobUser; do
  gcloud projects add-iam-policy-binding $PID --member="serviceAccount:$SA" --role=$R --condition=None
done
gcloud iam service-accounts add-iam-policy-binding $SA \
  --member="user:$(gcloud config get-value account)" --role=roles/iam.serviceAccountUser

# Deploy: public UI + private worker (same image)
export AIRLOCK_TOKEN=$(openssl rand -hex 20)   # operator token for privileged endpoints
ENVS="GOOGLE_CLOUD_PROJECT=$PID,GOOGLE_CLOUD_LOCATION=global,AUDIT_TOPIC=airlock-audit,\
WORK_TOPIC=airlock-work,ARMOR_LOCATION=us-central1,ARMOR_TEMPLATE=airlock,\
AIRLOCK_TOKEN=$AIRLOCK_TOKEN,MAX_LLM_CALLS=8"
gcloud beta run deploy airlock --source . --region us-central1 --service-account $SA \
  --set-env-vars "$ENVS" --allow-unauthenticated --timeout 900 \
  --execution-environment gen2 --sandbox-launcher --min-instances 1
gcloud beta run deploy airlock-worker --source . --region us-central1 --service-account $SA \
  --set-env-vars "$ENVS,PUSH_SA=airlock-push@$PID.iam.gserviceaccount.com" \
  --no-allow-unauthenticated --memory 2Gi --cpu 2 --concurrency 6 --max-instances 10 \
  --timeout 900 --execution-environment gen2 --sandbox-launcher

# Push subscription: ack deadline MUST exceed item runtime (20-30s), or you pay twice
WURL=$(gcloud run services describe airlock-worker --region us-central1 --format='value(status.url)')
PN=$(gcloud projects describe $PID --format='value(projectNumber)')
PS=service-$PN@gcp-sa-pubsub.iam.gserviceaccount.com
gcloud run services add-iam-policy-binding airlock-worker --region us-central1 \
  --member="serviceAccount:airlock-push@$PID.iam.gserviceaccount.com" --role=roles/run.invoker
gcloud iam service-accounts add-iam-policy-binding airlock-push@$PID.iam.gserviceaccount.com \
  --member="serviceAccount:$PS" --role=roles/iam.serviceAccountTokenCreator
gcloud pubsub topics add-iam-policy-binding airlock-dlq --member="serviceAccount:$PS" --role=roles/pubsub.publisher
gcloud pubsub subscriptions create airlock-work-push --topic=airlock-work \
  --push-endpoint="$WURL/worker" --push-auth-service-account="airlock-push@$PID.iam.gserviceaccount.com" \
  --ack-deadline=600 --min-retry-delay=10s --max-retry-delay=600s \
  --dead-letter-topic=airlock-dlq --max-delivery-attempts=5
gcloud pubsub subscriptions add-iam-policy-binding airlock-work-push --member="serviceAccount:$PS" --role=roles/pubsub.subscriber

# Verify agents, then run
U=$(gcloud run services describe airlock --region us-central1 --format='value(status.url)')
curl -XPOST "$U/ci/complaint_agent" -H "X-Airlock-Token: $AIRLOCK_TOKEN"
curl -XPOST "$U/ci/ticket_agent"    -H "X-Airlock-Token: $AIRLOCK_TOKEN"
open "$U/mission?lang=en"
```

## Tests

```bash
pip install -r requirements.txt pytest
GOOGLE_CLOUD_PROJECT=ci python -m pytest test_policy.py -q    # 24 tests, deterministic, no LLM
```

They cover the parts that must not regress: the `danger()` predicate, the block→grade flow, audit
isolation across concurrent runs, single-use payload-bound approvals, false-positive boundaries, and
CI fingerprint invalidation.

## Engineering notes (things that bite)

- **Ack deadline vs item runtime.** Items take 20–30s; the Pub/Sub default is 10s. Left alone, every
  message is redelivered and refunds are paid two or three times. Set `--ack-deadline=600`, and make
  the ledger itself idempotent (`refunds/{item_id}` via `create()`), not just a flag.
- **Releasing the lease on transient failure.** We take a lease per item to stop double-processing.
  If a 429 leaves the lease behind, the redelivery is discarded as a duplicate and the item is lost
  forever. Transient errors release the lease and return 503 so the subscription can retry — this
  took a 200-item run from 10 permanently failed to 0.
- **`max_llm_calls`.** ADK defaults to 500. Without a bound, an agent hunting for data it does not
  have looped 20+ tool calls, hit the 150s timeout, and then took a 429 with it. Set it to 8.
- **Sync tools block the event loop.** A 25s sandbox exec stalls every other item on the same
  instance. All tools are `async` and push blocking I/O through `to_thread`; contextvars propagate, so
  the per-run audit context still follows each call.
- **`/healthz` is swallowed by Cloud Run's front end** — use a different path (`/ready`).
- **Gemini 3.5 is on Vertex's `global` endpoint**, while Firestore is regional (`us-central1`).

## Honest limits

- **We do not call a few hundred items "massive".** The dataset is 3.4M rows and the scan really
  reads 1.7GB; the number of items *acted on* per run is in the hundreds. Scale is shown by shape —
  no shared lock, Cloud Run scaling out on its own, measured cost per item — not by a big number.
- **"Zero breaches under governance" is a structural consequence**, not a coverage claim: the policy
  and the grader evaluate the same `danger()` predicate, so a blocked call can never be scored as
  executed. It verifies enforcement. It does not prove the predicate catches every threat.
- **Whether an attack lands is model-dependent** (0/13 against one agent, 8/8 against another). We
  report both rather than the flattering one.
- **L1 is best-effort.** Model Armor's threshold was raised from `LOW_AND_ABOVE` to `HIGH` after a
  legitimate Japanese request ("reimburse $200 and email a confirmation") was blocked at MEDIUM
  confidence. The attack that then fell below the threshold — a secret posted to an external webhook —
  was verified to be stopped by L2 instead. That division of labour is the point of having layers.
- **Similarly for L2's secret detection**: matching the bare word "card" blocked a legitimate refund
  confirmation email, so it now matches secrets that carry values, not billing vocabulary.
- **The payment gateway is simulated.** The ledger, outbox, outbound HTTP and code execution are real.
- **`--sandbox-launcher` is a preview feature**; where it is unavailable, L3 degrades gracefully and
  L1/L2 still enforce.
- **Cases here are days old, not weeks.** The mechanism is not time-bounded, but the recorded history is.
