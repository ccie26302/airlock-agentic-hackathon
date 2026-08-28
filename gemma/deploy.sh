#!/usr/bin/env bash
# Gemma 3 on Cloud Run GPU (NVIDIA L4), private. Called only by the worker.
set -euo pipefail
PID=${PID:-forward-vector-470012-n8}
REGION=${REGION:-us-central1}
IMG="$REGION-docker.pkg.dev/$PID/app/gemma3-ollama:latest"

gcloud builds submit --project "$PID" --region "$REGION" \
  --tag "$IMG" --machine-type=e2-highcpu-8 --timeout=1800s gemma/

# --gpu-zonal-redundancy off keeps L4 on the on-demand pool (no quota request).
# min-instances 0: the GPU only costs while an item is actually being triaged.
gcloud beta run deploy gemma \
  --project "$PID" --region "$REGION" --image "$IMG" \
  --gpu 1 --gpu-type nvidia-l4 --no-gpu-zonal-redundancy \
  --cpu 8 --memory 32Gi --max-instances 1 --min-instances 0 \
  --concurrency 4 --timeout 600 --no-allow-unauthenticated \
  --execution-environment gen2

URL=$(gcloud run services describe gemma --project "$PID" --region "$REGION" --format='value(status.url)')
echo "GEMMA_URL=$URL"

# The worker's SA must be allowed to invoke it — the service stays closed to everyone else.
gcloud run services add-iam-policy-binding gemma --project "$PID" --region "$REGION" \
  --member="serviceAccount:airlock-run@$PID.iam.gserviceaccount.com" --role=roles/run.invoker
