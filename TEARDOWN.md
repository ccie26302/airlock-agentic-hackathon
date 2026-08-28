# 後始末（提出が終わったら実行）

## 1. Gemma の Vertex エンドポイント（一番高い / 0にスケールしない）
```bash
PID=forward-vector-470012-n8
EP=mg-endpoint-d4e3563a-4d99-4f32-9446-2285e85810d4
DM=$(gcloud ai endpoints describe $EP --region us-central1 --project $PID \
      --format='value(deployedModels[0].id)')
gcloud ai endpoints undeploy-model $EP --deployed-model-id=$DM \
  --region us-central1 --project $PID --quiet
gcloud ai endpoints delete $EP --region us-central1 --project $PID --quiet
```
L4 を 1 枚常時 = 約 $0.7/時。ここを止めるのが最優先。

## 2. Cloud Run の最小インスタンス（撮影用に上げてある）
```bash
gcloud run services update airlock        --region us-central1 --project $PID --min-instances 0
gcloud run services update airlock-worker --region us-central1 --project $PID --min-instances 0
```
サービス自体は消さない（審査中も URL は生きている必要がある）。

## 3. 触らないもの
- Firestore（ケース・監査・台帳）: 審査で参照される
- BigQuery: 公開データセットなので費用は走査時のみ
