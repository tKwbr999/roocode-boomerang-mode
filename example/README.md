# GoTodo - Go + PostgreSQL ToDo Application

## 1. プロジェクト概要

Go と PostgreSQL を使用した RESTful API ベースの ToDo アプリケーションです。
クリーンアーキテクチャを採用し、保守性と拡張性を考慮した設計を目指します。

**技術スタック**:
- Go 1.21+
- PostgreSQL 15+
- Gin (Web Framework)
- GORM (ORM)
- Docker & Docker Compose

## 2. 機能一覧

- ユーザー認証 (登録、ログイン)
- ユーザー情報管理
- ToDo リスト管理 (CRUD)
- ToDo タスク管理 (CRUD, 完了状態切替, フィルタリング, ソート)
- タグ管理 (CRUD)
- ToDo とタグの関連付け

詳細な API 仕様は Swagger ドキュメントを参照してください ( `make swagger` で生成後、 `/docs/index.html` を参照)。

## 3. ディレクトリ構造

```
./
├── cmd/api/main.go          # アプリケーションのエントリーポイント
├── internal/                # 内部ロジック (非公開)
│   ├── domain/              # ドメインモデル (Entity, Repository I/F, Service)
│   ├── usecase/             # ビジネスロジック
│   ├── interface/           # 外部インターフェース (API Handler, Repository Impl)
│   └── infrastructure/      # インフラ層 (DB, Validator)
├── pkg/                     # 公開可能パッケージ (Config, Auth, Logger, Utils)
├── scripts/                 # スクリプト (Migration, Seed)
├── .env.example             # 環境変数サンプル
├── .gitignore               # Git 除外設定
├── docker-compose.yml       # Docker Compose 設定
├── Dockerfile               # Docker ビルド設定
├── go.mod                   # Go モジュール定義
├── go.sum                   # 依存関係チェックサム
├── Makefile                 # Make コマンド定義
└── README.md                # このファイル
```

## 4. 開発環境セットアップ

### 4.1 必要条件

- Go 1.21 以上
- Docker, Docker Compose
- Make
- migrate CLI ([インストール手順](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate))
- golangci-lint ([インストール手順](https://golangci-lint.run/usage/install/))
- swag CLI ([インストール手順](https://github.com/swaggo/swag#install))

### 4.2 初期セットアップ手順

1.  **リポジトリをクローン:**
    ```bash
    git clone <repository-url>
    cd roocode-boomerang-mode/example
    ```

2.  **環境設定ファイルの作成:**
    ```bash
    cp .env.example .env
    ```
    必要に応じて `.env` ファイル内のデータベース接続情報や JWT シークレットなどを編集してください。

3.  **Docker コンテナの起動:**
    ```bash
    make docker-up
    ```
    これにより PostgreSQL データベースが起動します。

4.  **データベースマイグレーションの実行:**
    ```bash
    make migrate-up
    ```

5.  **依存関係のインストール:**
    ```bash
    go mod tidy
    ```

6.  **開発サーバーの起動:**
    ```bash
    make run-dev
    ```
    デフォルトでは `http://localhost:8080` でサーバーが起動します。

## 5. 主要な Make コマンド

- `make run-dev`: 開発サーバーを起動します (ホットリロード対応)。
- `make build`: アプリケーションバイナリを `bin/` ディレクトリにビルドします。
- `make test`: ユニットテストを実行します。
- `make test-coverage`: テストカバレッジレポートを生成します (`coverage.html`)。
- `make migrate-up`: データベースマイグレーションを適用します。
- `make migrate-down`: 最後のマイグレーションをロールバックします。
- `make migrate-create name=<migration_name>`: 新しいマイグレーションファイルを作成します。
- `make lint`: `golangci-lint` を使用してコードをリントします。
- `make swagger`: Swagger (OpenAPI) ドキュメントを `docs/` ディレクトリに生成します。
- `make docker-build`: アプリケーションの Docker イメージをビルドします。
- `make docker-up`: Docker Compose を使用してサービス (API, DB) を起動します。
- `make docker-down`: Docker Compose で起動したサービスを停止します。
- `make docker-logs`: 実行中の Docker コンテナのログを表示します。
- `make clean`: ビルド成果物やカバレッジレポートを削除します。

## 6. その他

- **エラーハンドリング**: API は標準化されたエラーレスポンス形式を使用します。詳細はイシューを参照してください。
- **認証**: JWT を使用した Bearer 認証が必要です。
- **セキュリティ**: イシューに記載されたセキュリティ対策を実装予定です。
- **パフォーマンス**: イシューに記載されたパフォーマンス最適化策を実装予定です。
- **ロギング**: `zap` を使用した構造化ログを出力します。
