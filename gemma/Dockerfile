# Gemma 3 on Cloud Run GPU (NVIDIA L4) via Ollama.
# ★モデルはイメージに焼き込む: 起動時に3GBを取りに行くとコールドスタートが分単位になる。
FROM ollama/ollama:latest

ENV OLLAMA_HOST=0.0.0.0:8080 \
    OLLAMA_MODELS=/models \
    OLLAMA_KEEP_ALIVE=-1 \
    OLLAMA_NUM_PARALLEL=4

# ビルド中に一度だけ serve を上げて pull する
RUN ollama serve & \
    sleep 8 && \
    ollama pull gemma3:4b && \
    pkill ollama || true

ENTRYPOINT ["ollama"]
CMD ["serve"]
