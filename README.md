# SpamGuard Bot（py-cord）

Discordサーバー向けのスパム対策Botです。  
連投・同文連投・URL乱投・過剰メンションをスコア方式で検知し、閾値超過時に自動モデレーションを実行します。

## 主な機能
- スパム検知（スコア加算）
  - 短時間の連投
  - 同一内容の連続投稿
  - URLの過剰投稿
  - 過剰メンション
  - 新規作成アカウントへの加点
- 自動モデレーション
  - 該当メッセージ削除
  - ユーザーのタイムアウト
  - ログチャンネルへの記録
- サーバーごとの設定管理
  - スラッシュコマンドから各閾値を変更
  - 例外ロール・例外チャンネルの管理

## 必要なDiscord権限
- Read Messages
- Message Content Intent
- Manage Messages
- Moderate Members
- Send Messages

## セットアップ
1. 依存関係をインストール
```bash
pip install -r requirements.txt
```

2. 環境変数ファイルを作成
```bash
cp .env.example .env
```

3. 設定ファイルをテンプレートから作成
```bash
cp config.example.json config.json
```

4. `.env` を編集
```env
DISCORD_TOKEN=your_token
SPAMGUARD_CONFIG_PATH=config.json
```

5. 起動
```bash
python bot.py
```

## 設定コマンド
- `/spamguard status` : 現在の設定表示
- `/spamguard setting bulk` : 各種しきい値をまとめて更新
- `/spamguard setting log_setup` : ログチャンネル設定 + 閲覧制限適用
- `/spamguard setting log_viewer` : ログ閲覧ロールを付与/剥奪
- `/spamguard setting log_clear` : ログチャンネル解除
- `/spamguard set <key> <value>` : 上級者向けの直接変更
- `/spamguard ignore add <role/channel>` : 例外追加
- `/spamguard ignore remove <role/channel>` : 例外削除

## 設定ファイル
- `config.example.json` : 共有用テンプレート
- `config.json` : 実運用設定（`.gitignore` で除外）

初期値は `config.example.json` を参照してください。

## テスト
```bash
pytest -q
```

## 関連ドキュメント
- 詳細要件定義: `Readme.md`
