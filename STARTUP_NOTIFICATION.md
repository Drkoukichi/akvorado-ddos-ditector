## 起動時通知機能 実装完了

### 実装内容

Docker Compose起動時に、以下の情報を含む通知をWebhookに送信する機能を追加しました:

#### 1. **起動通知の内容**
- ✅ アプリケーション起動完了の通知
- 📊 現在のトラフィック統計
  - 総外部トラフィック量 (Gbps)
  - トップ宛先IPの情報
  - 検出された攻撃の数
- 🔍 送信元IPのAbuseIPDB チェック結果
  - サンプルIPの評判情報
  - 報告数とスコア
  - 国とISP情報

#### 2. **追加されたファイル/機能**

**ddos_detector.py:**
- `NotificationManager.send_startup_notification()` - 起動通知の送信
- `NotificationManager._format_startup_message()` - メッセージのフォーマット
- `NotificationManager._send_discord_startup()` - Discord起動通知
- `NotificationManager._send_slack_startup()` - Slack起動通知
- `DDoSDetector.get_startup_stats()` - 起動時の統計情報取得
- AbuseIPDB設定の読み込み機能

**設定ファイル:**
- `config.yaml.example` - AbuseIPDB設定を追加
- `.env.example` - 環境変数にAbuseIPDB設定を追加

**テストファイル:**
- `test_startup_notification.py` - 起動通知機能のテスト

#### 3. **通知メッセージ例**

```
✅ DDoS Detector Started Successfully ✅

Start Time: 2025-12-09 09:23:21
Status: Monitoring Active

📊 Current Traffic Summary:
Total External Traffic: 2.50 Gbps
Top Destinations: 5
Active Attacks: 1

🎯 Top Destination:
IP: 203.0.113.10
Traffic: 1.80 Gbps
Unique Sources: 3,500

🔍 Sample Source IP Check (AbuseIPDB):
IP: 198.51.100.42
Total Reports: 127
Abuse Score: 85%
Country: US
ISP: Example ISP Inc.
```

#### 4. **動作フロー**

1. アプリケーション起動
2. ClickHouseに接続
3. 直近5分間（time_window）のトラフィック統計を取得
4. 攻撃検知ロジックを実行
5. トップ宛先の送信元IPの1つをAbuseIPDBでチェック
6. 統計情報とAbuseIPDB結果をまとめて通知
7. 通常の監視ループを開始

#### 5. **設定方法**

**環境変数:**
```bash
ABUSEIPDB_ENABLED=true
ABUSEIPDB_API_KEY=your_api_key_here
ABUSEIPDB_MAX_AGE_DAYS=90
```

**config.yaml:**
```yaml
abuseipdb:
  enabled: true
  api_key: "your_api_key_here"
  max_age_days: 90
```

#### 6. **テスト方法**

```bash
# 起動通知のテスト
python test_startup_notification.py

# 実際にアプリを起動
docker compose up -d

# ログで確認
docker compose logs -f ddos-detector
```

#### 7. **通知の色分け**

**Discord:**
- 🟢 緑 (0x00FF00): 攻撃なし
- 🟡 黄 (0xFFCC00): 攻撃検出あり

**Slack:**
- `good`: 攻撃なし
- `warning`: 攻撃検出あり

### 利点

- 🚀 アプリケーション起動を即座に確認可能
- 📊 起動時点でのネットワーク状況を把握
- 🔍 疑わしいIPを早期発見
- 💡 監視が正常に開始されたことを確認
- 📱 Discord/Slackでリアルタイム通知

### 注意事項

- AbuseIPDB APIは無料プランで1日1,000リクエストまで
- 起動時は1つの送信元IPのみチェック（APIクォータ節約）
- ClickHouseに接続できない場合はエラーログが出力されます
- 通知送信に失敗してもアプリケーションは継続動作します
