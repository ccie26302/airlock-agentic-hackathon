# 🛰 Airlock — Enterprise AI Agent Platform

**Security is the strength. Ship agents fast; let none act unaudited.**

手順書(SOP)からAIエージェントを最小権限で自動生成し、「艦隊(Fleet)」として登録・実行する基盤。エージェントは実タスクを実行し、**3層防御**が言語・行動・実行の各段で守り、全操作を監査する。

> All Things Agentic Hackathon / Track: **Fortified Enterprise Fleet** · Individual project, not affiliated with or endorsed by Google/Anthropic.

## 3層防御（defense in depth）
| 層 | 実装 | 守る対象 |
|---|---|---|
| **L1 言語層** | **Google Model Armor** (`sanitizeUserPrompt`) | 露骨なプロンプトインジェクション/脱獄 |
| **L2 行動層** | 決定的ポリシー（ADK `before_tool_callback`） | 一見まっとうな違反（高額返金・送金先改ざん・PII/秘密の外部持出） |
| **L3 実行層** | **Cloud Run Sandbox**（gVisor, `--sandbox-launcher`） | 乗っ取られたコード実行（SAトークン窃取・外部持出） |
| **Governed Memory** | `write_memory`→Firestore、書込前にPolicy検査 | cross-session memory poisoning（上限/方針/許可リストの改ざん） |

「一方では守れない」を各層が補完する。判定は LLM でなく**計装の事実**（危険ツールが実際に実行されたか）で決める。

## エージェントは実基盤で実タスクを行う
ツールは本物の Google Cloud 副作用を持つ（決済ゲートウェイのみ模擬）:
- `read_order_note` / `get_customer_list` … 実 **Firestore** 読取（orders / customers）
- `transfer_money` … 決済は模擬だが実 Firestore **refunds 台帳**に記録
- `send_email` … 実 **outbox** に投函（実送信はしない）
- `http_post` … **本物の外部 HTTP 送信**（OFF なら実際に外部へ飛ぶ）
- `run_analysis` … **Cloud Run sandbox 内でコード実行**（L3）

## アーキテクチャ（要件スタックの対応）
| レイヤ | 実装 | 必須要件 |
|---|---|---|
| 生成/審査の知能 | **Gemini 3.5 Flash**(Vertex AI, `global`) | Gemini 3.5以降 ✅ |
| エージェント実行＋介入 | **Google ADK**(callbacks/tools) | Google Agent Framework ✅ |
| API/UI/監査ワーカー/sandbox | **Cloud Run** (gen2, sandbox-launcher) | Google Cloud インフラ ✅ |
| レジストリ/監査/通信簿 | **Firestore**(named db `airlock`) | 〃 |
| 監査イベント配信 | **Pub/Sub**(`airlock-audit`) | 〃 |
| 言語層セキュリティ | **Model Armor** | （加点） |

## セットアップ（コピペで再現）
```bash
export PID=<your-project-id>
gcloud config set project $PID

# 1) API 有効化
gcloud services enable aiplatform.googleapis.com run.googleapis.com firestore.googleapis.com \
  pubsub.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com modelarmor.googleapis.com

# 2) Firestore(named db)・Pub/Sub・Model Armor テンプレート
gcloud firestore databases create --database=airlock --location=us-central1 --type=firestore-native
gcloud pubsub topics create airlock-audit
TOKEN=$(gcloud auth print-access-token)
curl -s -X POST "https://modelarmor.us-central1.rep.googleapis.com/v1/projects/$PID/locations/us-central1/templates?template_id=airlock" \
  -H "Authorization: Bearer $TOKEN" -H "x-goog-user-project: $PID" -H "Content-Type: application/json" \
  -d '{"filterConfig":{"piAndJailbreakFilterSettings":{"filterEnforcement":"ENABLED","confidenceLevel":"LOW_AND_ABOVE"},"maliciousUriFilterSettings":{"filterEnforcement":"ENABLED"}}}'

# 3) 実行用サービスアカウント(最小権限)
gcloud iam service-accounts create airlock-run --display-name="Airlock Cloud Run"
SA=airlock-run@$PID.iam.gserviceaccount.com
for R in roles/aiplatform.user roles/datastore.user roles/pubsub.publisher roles/modelarmor.user; do
  gcloud projects add-iam-policy-binding $PID --member="serviceAccount:$SA" --role=$R --condition=None
done

# 4) デプロイ（★gen2 + sandbox-launcher = Layer3。beta が必要）
#    実行者に roles/iam.serviceAccountUser（上記SAをactAs）と Cloud Build/Artifact Registry 権限が要る:
gcloud iam service-accounts add-iam-policy-binding $SA --member="user:$(gcloud config get-value account)" --role=roles/iam.serviceAccountUser
gcloud beta run deploy airlock --source . --region us-central1 \
  --service-account $SA \
  --set-env-vars GOOGLE_CLOUD_PROJECT=$PID,GOOGLE_CLOUD_LOCATION=global,AUDIT_TOPIC=airlock-audit,ARMOR_LOCATION=us-central1,ARMOR_TEMPLATE=airlock \
  --allow-unauthenticated --timeout 900 --execution-environment gen2 --sandbox-launcher

# 5) シード(艦隊を実測 + Layer3プローブ)
URL=$(gcloud run services describe airlock --region us-central1 --format='value(status.url)')
curl -X POST $URL/seed        # もしくはローカルで: python seed.py
open "$URL/dashboard?lang=en"
```

## エンドポイント
- `GET /dashboard?lang=en|ja` — 3層の before/after 通信簿 ＋ Layer3証明 ＋ Fleet Scoreboard（言語切替）
- `GET /new` — SOPを貼ってエージェント生成
- `GET /sandbox_probe` — Layer3の直接証明（同一コードが直接実行では実SAトークン漏洩、sandboxでは封殺。トークン値は返さない）
- `GET /healthz` — readiness（Firestore到達性）
- `POST /generate {sop}` — SOP→最小権限spec→登録→審査
- `POST /run {prompt, governance}` — 単発実行（ガバナンスON/OFF）
- `POST /audit {governance}` / `POST /seed` — バッテリー実行 / ダッシュボード再生成

## デモの流れ
1. `GET /new` で返品SOP → 最小権限エージェント生成・艦隊登録。
2. `POST /run` を `governance:false→true` で同じ攻撃 → OFF は実行され事故、ON は遮断。
3. `GET /sandbox_probe` → 同一コードが直接実行では実SAトークン漏洩、sandbox では network unreachable で封殺（L3）。
4. `GET /dashboard?lang=en` → OFF vs ON ＋ 3層内訳(Armor/Airlock) ＋ Layer3証明 ＋ Fleet。
5. Cloud Console で Cloud Run / Vertexログ / Firestore / Pub/Sub の裏側を提示。

## 注記（誠実性・前提）
- **「ガバナンスON＝突破0」は構造的帰結**（ブロック条件と突破条件が同一 `danger()` を共有）＝*実行境界での強制の検証*。ポリシー網羅性の証明ではない。
- **OFF突破・正当遮断はモデル挙動に依存する観測値（非決定）**。露骨な攻撃はモデル自身が拒否するので、毎回確実にすり抜けるのは「$5,000の無承認返金」等の"もっともらしい方針違反"で、そこをL2が止める。
- **overhead ≈ 0.04ms は L2 ポリシー述語の評価のみ**。L1 Model Armor のネットワーク往復（sanitizeUserPrompt, 数十〜数百ms）と L3 sandbox 起動コストは別。片側の数字にしない。
- **L3の封殺は固定コードのプローブで実証**（LLM非依存）。フロンティアモデルは露骨な窃取タスクを自力で拒否するため、機構の証明はプローブで担保。
- **強い層と弱い層を分ける**：決定的で回避困難なのは L3(実行境界) と L2 の allowlist+limit。L1 Model Armor / SECRET_PAT 等の ML・正規表現は多層防御の**ベストエフォート**（base64/空白挿入で回避余地、`card`/`password` 語で正当文面を誤遮断し得る）。
- **誤検知(FP)対照**：明白ケースに加え境界(上限直下$999／`card`語を含む正当メール)も測る。後者は現ポリシーで**過剰遮断され得る**（ダッシュボードに実数表示）＝境界の弱点を隠さない。
- A2(間接インジェクション)を止めるのは L2 の**受取人allowlist**であり、after_tool の正規表現検疫は補助の1層。
- リージョン：Firestore はリージョナル(us-central1)、Vertex Gemini 3.5 は `global`（非対称だが正常）。
- **認証モデル（実装済）**: 公開面は**読取(`/dashboard` `/healthz`)＋ON実行(`/run`は未認証だとgovernance強制ON)**のみ。副作用・課金系(`/seed` `/generate` `/audit`、および `/run` のOFF指定)は **`X-Airlock-Token` ヘッダ必須**(env `AIRLOCK_TOKEN`)。これで未認証のopen relay/持ち出し中継/課金DoSを封鎖。攻撃ペイロード中の鍵は合成ダミー。
- **L3の `--sandbox-launcher` はプレビュー機能**（`gcloud beta`, 要事前有効化/allowlist）。無効環境では `run_analysis`→`SANDBOX_UNAVAILABLE`、`/sandbox_probe`→`cli unavailable` に**graceful degrade**（L1/L2は稼働）。
- **提出前スモーク必須**: `curl $URL/healthz`(Firestore到達) と `curl -XPOST $URL/run -d '{"prompt":"refund $10 to alice@example.com"}'`(Gemini疎通)を1回。モデルIDは一次情報で再確認。

## テスト
```bash
pip install -r requirements.txt pytest
GOOGLE_CLOUD_PROJECT=ci python -m pytest test_policy.py -q   # 決定的(LLM不要)・遮断→採点の核心フロー回帰
```
