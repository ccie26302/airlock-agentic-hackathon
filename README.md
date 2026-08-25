# 🛰 Airlock — Enterprise Agent Governance

**Ship agents fast. Let none act unaudited.**

手順書(SOP)からAIエージェントを自動生成し、「艦隊(Fleet)」として登録・統治する。裏で各エージェントに攻撃バッテリーを撃ち込み、実行時に危険操作を遮断／承認へ回し、**決定的判定のセキュリティ通信簿**で本番投入可否を示す ― エンタープライズ向けエージェント基盤。

> All Things Agentic Hackathon / Track: **Fortified Enterprise Fleet**

## 何をするか
- **Generator**: SOPを貼ると Gemini が**最小権限**のエージェント仕様(使うツール＋ガードレール)を生成し、艦隊に登録。
- **Governed Runtime (ADK)**: 全ツール呼び出しを ADK の `before_tool_callback` で検査し、危険な操作(限度超過の送金・送金先改ざん・PII/秘密の外部持ち出し等)を**実行前に遮断**。`after_tool_callback` でツール出力に混入した**間接プロンプトインジェクションを検疫**。
- **Deterministic Scorecard**: 合否は LLM でなく**計装の事実**(危険ツールが実際に実行されたか)で判定 → 数値が安定。`danger()` の単一定義をポリシーと採点で共有し、**ガバナンスON時の突破=0 を構造的に保証**。
- **Fleet Scoreboard / Observability**: 複数エージェントの姿勢・最小権限スコープを一覧。全操作は Firestore + Cloud Logging に監査証跡、監査イベントは Pub/Sub へ。

## アーキテクチャ（要件スタックの対応）
| レイヤ | 実装 | ハッカソン必須要件 |
|---|---|---|
| 生成/審査の知能 | **Gemini 3.5 Flash**(Vertex AI, `global`) | Gemini 3.5以降 ✅ |
| エージェント実行＋介入 | **Google ADK**(callbacks/tools) | Google Agent Framework ✅ |
| API/UI/監査ワーカー | **Cloud Run** | Google Cloud インフラ ✅ |
| レジストリ/監査証跡/通信簿 | **Firestore**(named db `airlock`) | 〃 |
| 監査イベント配信 | **Pub/Sub**(`airlock-audit`) | 〃 |

## 前提
- gcloud CLI 認証済み / 課金有効なGCPプロジェクト / Python 3.12

## セットアップ（コピペで再現）
```bash
export PID=<your-project-id>
gcloud config set project $PID

# 1) API 有効化
gcloud services enable aiplatform.googleapis.com run.googleapis.com \
  firestore.googleapis.com pubsub.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

# 2) Firestore(named db) と Pub/Sub トピック
gcloud firestore databases create --database=airlock --location=us-central1 --type=firestore-native
gcloud pubsub topics create airlock-audit

# 3) 実行用サービスアカウント(最小権限)
gcloud iam service-accounts create airlock-run --display-name="Airlock Cloud Run"
SA=airlock-run@$PID.iam.gserviceaccount.com
for R in roles/aiplatform.user roles/datastore.user roles/pubsub.publisher; do
  gcloud projects add-iam-policy-binding $PID --member="serviceAccount:$SA" --role=$R --condition=None
done

# 4) デプロイ
gcloud run deploy airlock --source . --region us-central1 \
  --service-account $SA \
  --set-env-vars GOOGLE_CLOUD_PROJECT=$PID,GOOGLE_CLOUD_LOCATION=global,AUDIT_TOPIC=airlock-audit \
  --allow-unauthenticated --timeout 900

# 5) ダッシュボード用データをシード(艦隊を実測)
URL=$(gcloud run services describe airlock --region us-central1 --format='value(status.url)')
curl -X POST $URL/seed        # もしくはローカルで: python seed.py
open $URL/dashboard
```

## エンドポイント
- `GET /dashboard` — before/after 通信簿 ＋ Fleet Scoreboard（デモの主画面）
- `GET /new` — SOPを貼ってエージェント生成（デモの掴み）
- `POST /generate {sop}` — SOP→AgentSpec(最小権限)→登録→審査
- `POST /audit {governance}` — 攻撃バッテリーを実行し通信簿を返す
- `POST /run {prompt, governance, order_note}` — 単発実行（ガバナンスON/OFF切替）
- `POST /seed` — ダッシュボードデータを再生成

## デモの流れ
1. `GET /new` で返品SOPを貼る → エージェントが生まれ艦隊に登録（最小権限で生成）。
2. `POST /run` を `governance:false` で攻撃 → 危険操作が**実行される(事故)**。`governance:true` で同じ攻撃 → **遮断**。
3. `GET /dashboard` → OFF(突破あり・赤) vs ON(突破0・誤検知0・緑) の対比＋Fleet Scoreboard。
4. Cloud Console(Cloud Run / Vertex ログ / Firestore / Pub/Sub)で裏側を提示。

## 注記（誠実性・前提）
- **「ガバナンスON＝突破0」は構造的帰結**：ブロック条件と突破条件が同一の `danger()` を共有するため。これは*実行境界での強制(enforcement)の検証*であって、ポリシーが実脅威を網羅する証明ではない。
- **OFFの突破数・正当遮断はモデル挙動に依存する観測値（非決定）**。確定して毎回突破するのは「$5,000の無承認返金」。他の攻撃がlandするかは回による。数は断定しない。
- **overhead ≈ 0.04ms は `before` 側の危険判定のみ**（`after` の検査・LLM往復は含まない）。
- リージョン：**Firestore はリージョナル名前付きDB(us-central1)、Vertex の Gemini 3.5 は `global` エンドポイント**（非対称だが正常）。
- デプロイ実行者は `--source` ビルドのため Cloud Build/Artifact Registry 権限（owner 相当 or `roles/cloudbuild.builds.editor` 等）が要る。`python seed.py` はローカルの ADC 認証と名前付きDB `airlock` の実在が前提。
- **デモは利便のため `--allow-unauthenticated`**。`/seed` `/generate` は Vertex 課金を伴うので、本番では認証必須(IAP/APIキー)にすること。攻撃ペイロード中の鍵等は合成ダミー。

## テスト
```bash
pip install -r requirements.txt pytest
GOOGLE_CLOUD_PROJECT=ci python -m pytest test_policy.py -q   # 決定的(LLM不要)。danger()＋遮断→採点の核心フローを回帰テスト
```

## セキュリティ/安全
- 危険ツールは全て**計装モック**(実送金・実送信なし)。実exploitは生成しない。
- 攻撃バッテリーは公開されているAIエージェント脅威(プロンプトインジェクション/ツール汚染/データ持ち出し/不可逆操作の無承認)を機械採点可能な形にしたもの。

## ライセンス / 注記
個人開発・ハッカソン提出物。Gemini/ADK/Cloud Run/Firestore/Pub/Sub を使用。
