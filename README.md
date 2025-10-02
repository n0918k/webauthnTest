# WebAuthn Demo アプリケーション

Flask と MySQL を用いて構築した WebAuthn (FIDO2) ベースのパスワードレス認証デモです。ブラウザが対応していれば、セキュリティキーやプラットフォーム認証器を用いて登録・ログインできます。

## 主な機能

- WebAuthn による FIDO2 認証器の登録とログイン
- MySQL によるユーザー・認証情報の永続化
- Bootstrap を利用したシンプルな UI
- `.env` などからオーバーライド可能な設定

## セットアップ手順

### 1. 依存関係のインストール

```bash
python -m venv venv
source venv/bin/activate  # Windows の場合は venv\Scripts\activate
pip install -r requirements.txt
```

### 2. MySQL の準備

以下はローカルで MySQL 8.x を利用する例です。

```sql
CREATE DATABASE webauthn CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'webauthn'@'localhost' IDENTIFIED BY 'webauthn';
GRANT ALL PRIVILEGES ON webauthn.* TO 'webauthn'@'localhost';
FLUSH PRIVILEGES;
```

接続情報を環境変数で変更する場合は `.env` を作成し、以下のように設定してください。

```dotenv
DATABASE_URI=mysql+pymysql://<user>:<password>@<host>:<port>/<database>
SECRET_KEY=ランダムな文字列
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:8000
WEBAUTHN_RP_NAME=WebAuthn Demo
```

### 3. アプリケーションの起動

```bash
export FLASK_APP=app:create_app
flask run --host=0.0.0.0 --port=8000
```

起動後、ブラウザで `http://localhost:8000` にアクセスして登録・ログインを試してください。

## ディレクトリ構成

```
.
├── app.py               # Flask アプリケーション本体
├── config.py            # 設定
├── requirements.txt     # 依存パッケージ
├── templates/           # Jinja2 テンプレート
└── static/              # CSS / JavaScript
```

## 注意事項

- WebAuthn を利用するには HTTPS が推奨されます。本番環境では TLS を必ず有効化してください。
- ブラウザが WebAuthn/FIDO2 に対応していない場合は動作しません。
- デモ用途のため、詳細なエラーハンドリングや管理機能は最小限です。