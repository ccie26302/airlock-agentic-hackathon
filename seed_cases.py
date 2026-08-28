import hashlib, time, json, sys
import main   # ハッシュ規約を本体と共有する(二重定義しない)
from google.cloud import bigquery, firestore
bq = bigquery.Client(project="forward-vector-470012-n8")
rows = list(bq.query("""
SELECT complaint_id, date_received, product, issue, company_name, state,
       consumer_complaint_narrative AS narrative
FROM `bigquery-public-data.cfpb_complaints.complaint_database`
WHERE consumer_complaint_narrative IS NOT NULL
  AND LENGTH(consumer_complaint_narrative) BETWEEN 300 AND 900
  AND product LIKE '%Credit card%'
ORDER BY date_received DESC LIMIT 3""").result())
db = firestore.Client(project="forward-vector-470012-n8", database="airlock")
now = time.time()
plan = [
 dict(dept="Customer Ops", agent="refund_agent", amount=2400.00,
      reason="Refund amount $2,400.00 exceeds the $1,000 auto-approval limit",
      question="Approve a $2,400.00 goodwill refund to the cardholder, or deny?"),
 dict(dept="Finance", agent="expense_agent", amount=980.00,
      reason="Payee on the request does not match the vendor of record",
      question="The request names a different payee than the vendor on file. Confirm?"),
 dict(dept="Customer Ops", agent="refund_agent", amount=1250.00,
      reason="Duplicate settlement suspected for the same billing dispute",
      question="A similar settlement was issued for this dispute. Approve a second payment?")]
ok = 0
for r, p in zip(rows, plan):
    cid = f"C-{r['complaint_id']}"
    # ★宛先とハッシュは main._action_hash と同じ規約に揃える。
    #   ずれると「保留中に金額/宛先が変わった」と判定され、承認が永久に通らない。
    payload = {"action": "transfer_money", "amount": p["amount"],
               "recipient": f"cardholder-{r['complaint_id']}@example.com"}
    db.collection("cases").document(cid).set({
      "case_id": cid, "status":"awaiting_approval", "department":p["dept"], "agent":p["agent"],
      "source": {"dataset":"bigquery-public-data.cfpb_complaints","complaint_id":str(r["complaint_id"]),
                 "product":r["product"],"issue":r["issue"],"company":r["company_name"],
                 "state":r["state"],"date_received":str(r["date_received"])},
      "narrative_excerpt": (r["narrative"] or "")[:400],
      "escalation_reason": p["reason"], "question_for_human": p["question"],
      "proposed_action": payload,
      "payload_hash": main._action_hash("transfer_money", payload),
      "context": [{"step":"read_source","note":"Pulled the complaint narrative from the warehouse"},
                  {"step":"classify","note":f"Classified as: {r['issue']}"},
                  {"step":"policy_check","note":p["reason"]},
                  {"step":"escalate","note":"Paused for human approval; no funds moved"}],
      "created_at": now, "updated_at": now, "human_touches": 0})
    print("CASE", cid, p["dept"], p["amount"]); ok += 1
print("SEEDED", ok, "cases at", time.strftime("%Y-%m-%d %H:%M", time.localtime(now)))
