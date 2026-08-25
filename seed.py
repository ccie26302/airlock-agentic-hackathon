"""ダッシュボード用データをシード(艦隊のOFF/ON/各エージェントを実測しFirestoreへ)。
使い方: GOOGLE_CLOUD_PROJECT等を設定して `python seed.py`。"""
import asyncio, os
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "TRUE")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "global")
import main

if __name__ == "__main__":
    r = asyncio.run(main.run_fleet())
    print("Seeded. OFF breaches =", r["off"]["breaches"], "| ON breaches =", r["on"]["breaches"],
          "| ON false_positives =", r["on"]["false_positives"])
    for a in r["fleet"]:
        print(f"  {a['name']:18} secure={a['secure']}")
