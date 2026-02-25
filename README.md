# イグライトポテンシャルベース (Ignite Potential Base)

野球パフォーマンスを科学で変えるサブスクリプションサービス

## 概要

- **フリープラン**: 無料記事・動画を閲覧可能
- **プレミアムプラン**: ¥1,500/月 - 全コンテンツアクセス
- 6カテゴリー: 技術、トレーニング、メンタル、栄養、コンディション、指導理論

## セットアップ

### 1. 依存パッケージのインストール

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. 環境変数の設定

`.env`ファイルを編集して各種APIキーを設定:
- `SUPABASE_URL` / `SUPABASE_SERVICE_KEY`: Supabaseプロジェクトの設定
- `STRIPE_SECRET_KEY` / `STRIPE_PUBLISHABLE_KEY`: Stripeダッシュボードから取得
- `STRIPE_PRICE_ID`: Stripeで作成したプライスID
- `SECRET_KEY`: Flaskセッション用シークレットキー

### 3. データベースのセットアップ

`setup.sql`をSupabase SQL Editorで実行

### 4. アプリの起動

```bash
source venv/bin/activate
python app.py
```

アプリは http://localhost:5001 で起動します

## 管理者ログイン

- メール: `coach@ignite.jp`
- パスワード: `admin123`（必ず変更してください）

## 技術スタック

- **Backend**: Flask 3.0 + Python
- **Database**: Supabase (PostgreSQL) via REST API
- **Payment**: Stripe
- **Templating**: Jinja2
- **Styling**: Vanilla CSS (dark sports theme)
