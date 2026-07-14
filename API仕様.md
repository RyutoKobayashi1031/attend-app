# サークル活動受付・出席管理システム API仕様

## 1. 概要

本APIは、サークルや団体の活動、メンバー、活動日、受付状況、出席率を管理するREST APIです。FlaskとPostgreSQLで実装され、JSON形式でデータを送受信します。

ログインユーザーは、`activity_users`で参加している活動とその配下のデータを、割り当てられた権限の範囲で操作できます。参加していない活動のIDを指定した場合は、データの存在を公開せず `404 Not Found` を返します。

### 活動権限

| API操作 | owner | staff | viewer |
| --- | :---: | :---: | :---: |
| 活動・メンバー・活動日・集計のGET | ✓ | ✓ | ✓ |
| 受付一覧GET | ✓ | ✓ | ✓ |
| 受付変更 | ✓ | ✓ | - |
| メンバー・活動日のPOST／PUT | ✓ | ✓ | - |
| メンバー・活動日のDELETE | ✓ | - | - |
| 活動のPUT／DELETE | ✓ | - | - |

`POST /api/activities`で活動を作成したユーザーは自動的にownerになります。権限管理用APIは提供していないため、メンバー権限の追加・変更・削除はWeb画面から行います。権限不足の場合は`403 Forbidden`を返します。

## 2. 共通仕様

### ベースURL

```text
http://127.0.0.1:5000
```

### リクエスト形式

JSONを送信する場合は、次のヘッダーを指定します。

```http
Content-Type: application/json
```

### 認証

`POST /api/login` 以外のエンドポイントは認証が必要です。ログインAPIで取得したトークンを次の形式で送信します。

```http
Authorization: Bearer <token>
```

APIトークンの有効期限は発行から30日です。サーバーにはトークンの平文ではなく、SHA-256ハッシュが保存されます。

### 成功レスポンス

```json
{
  "success": true,
  "message": "処理に成功しました。",
  "data": {}
}
```

返すデータがない場合は `data` が省略されます。

### エラーレスポンス

```json
{
  "success": false,
  "error": "エラーメッセージ"
}
```

### 日付と日時

- 活動日の入力形式は `YYYY-MM-DD` です。
- PostgreSQLの日付・日時は、通常RFC 1123形式でJSON化されます。
- ログインレスポンスの `expires_at` はISO 8601形式です。
- 未受付の場合、`checked_in_at` は `null` です。

### 主なHTTPステータスコード

| コード | 意味 |
| --- | --- |
| `200 OK` | 取得、更新、削除、ログイン、ログアウトに成功 |
| `201 Created` | 活動、メンバー、活動日の作成に成功 |
| `400 Bad Request` | JSONや必須項目がないなど、入力内容に不備がある |
| `401 Unauthorized` | ログイン失敗、またはトークンがない・無効・期限切れ |
| `403 Forbidden` | 活動には参加しているが、指定された操作を行う権限がない |
| `404 Not Found` | データが存在しない、またはアクセス権がない |
| `405 Method Not Allowed` | 指定されたHTTPメソッドに対応していない |
| `500 Internal Server Error` | サーバー内部でエラーが発生した |

## 3. エンドポイント一覧

| 分類 | メソッド | パス | 成功時 |
| --- | --- | --- | --- |
| 認証 | `POST` | `/api/login` | `200` |
| 認証 | `POST` | `/api/logout` | `200` |
| 認証 | `GET` | `/api/me` | `200` |
| 活動 | `GET` | `/api/activities` | `200` |
| 活動 | `POST` | `/api/activities` | `201` |
| 活動 | `GET` | `/api/activities/{activity_id}` | `200` |
| 活動 | `PUT` | `/api/activities/{activity_id}` | `200` |
| 活動 | `DELETE` | `/api/activities/{activity_id}` | `200` |
| メンバー | `GET` | `/api/activities/{activity_id}/members` | `200` |
| メンバー | `POST` | `/api/activities/{activity_id}/members` | `201` |
| メンバー | `PUT` | `/api/activities/{activity_id}/members/{member_id}` | `200` |
| メンバー | `DELETE` | `/api/activities/{activity_id}/members/{member_id}` | `200` |
| 活動日 | `GET` | `/api/activities/{activity_id}/sessions` | `200` |
| 活動日 | `POST` | `/api/activities/{activity_id}/sessions` | `201` |
| 活動日 | `PUT` | `/api/activities/{activity_id}/sessions/{session_id}` | `200` |
| 活動日 | `DELETE` | `/api/activities/{activity_id}/sessions/{session_id}` | `200` |
| 受付 | `GET` | `/api/activities/{activity_id}/sessions/{session_id}/attendance` | `200` |
| 受付 | `POST` | `/api/activities/{activity_id}/attendance/{attendance_id}/check_in` | `200` |
| 受付 | `POST` | `/api/activities/{activity_id}/attendance/{attendance_id}/cancel_check_in` | `200` |
| 受付 | `PUT` | `/api/activities/{activity_id}/attendance/{attendance_id}/note` | `200` |
| 集計 | `GET` | `/api/activities/{activity_id}/attendance/summary` | `200` |
| 集計 | `GET` | `/api/activities/{activity_id}/attendance/group_summary` | `200` |

## 4. 認証API

### 4.1 ログイン

```http
POST /api/login
```

認証は不要です。

| 項目 | 型 | 必須 | 説明 |
| --- | --- | --- | --- |
| `username` | string | はい | ユーザー名 |
| `password` | string | はい | パスワード |

リクエスト例：

```json
{
  "username": "admin",
  "password": "password"
}
```

レスポンス例：

```json
{
  "success": true,
  "message": "ログインしました。",
  "data": {
    "token": "xxxxxxxxxxxxxxxxxxxxxxxx",
    "expires_at": "2026-08-10T15:08:24.237504",
    "user": {
      "id": 1,
      "username": "admin"
    }
  }
}
```

ログインするたびに新しいトークンが発行されます。以前のトークンも、ログアウトまたは有効期限切れになるまでは利用できます。

### 4.2 ログアウト

```http
POST /api/logout
```

現在使用しているトークンを無効化します。リクエストボディは不要です。

```json
{
  "success": true,
  "message": "ログアウトしました。"
}
```

### 4.3 ログイン中ユーザー取得

```http
GET /api/me
```

```json
{
  "success": true,
  "message": "ユーザー情報を取得しました。",
  "data": {
    "user": {
      "id": 1,
      "username": "admin"
    }
  }
}
```

## 5. 活動API

### 5.1 活動一覧取得

```http
GET /api/activities
```

ログインユーザーが所有する活動を、作成日時の新しい順で返します。

```json
{
  "success": true,
  "message": "活動一覧を取得しました。",
  "data": {
    "activities": [
      {
        "id": 2,
        "name": "オーケストラ",
        "description": "定期練習の出席管理",
        "created_at": "Sat, 11 Jul 2026 03:27:33 GMT"
      }
    ]
  }
}
```

### 5.2 活動作成

```http
POST /api/activities
```

| 項目 | 型 | 必須 | 省略時 |
| --- | --- | --- | --- |
| `name` | string | はい | - |
| `description` | string | いいえ | 空文字 |

```json
{
  "name": "オーケストラ",
  "description": "定期練習の出席管理"
}
```

成功時は `201 Created` で、`data.activity` に作成した活動を返します。

### 5.3 活動詳細取得

```http
GET /api/activities/{activity_id}
```

`data.activity` に `id`、`user_id`、`name`、`description`、`created_at` を返します。

### 5.4 活動更新

```http
PUT /api/activities/{activity_id}
```

リクエスト項目は活動作成と同じです。部分更新ではないため、`name` は毎回必須です。`description` を省略すると空文字に更新されます。

### 5.5 活動削除

```http
DELETE /api/activities/{activity_id}
```

`data.deleted_activity` に削除した活動の `id`、`name`、`description` を返します。README記載の外部キー構成では、配下のメンバー、活動日、受付情報も削除されます。

## 6. メンバーAPI

### 6.1 メンバー一覧取得

```http
GET /api/activities/{activity_id}/members
```

所属区分、所属グループ、名前の昇順で返します。

```json
{
  "success": true,
  "message": "メンバー一覧を取得しました。",
  "data": {
    "activity": {
      "id": 2,
      "name": "オーケストラ"
    },
    "members": [
      {
        "id": 1,
        "name": "田中",
        "group_name": "企画班",
        "category": "2026年度",
        "note": "代表者",
        "created_at": "Sat, 11 Jul 2026 04:10:00 GMT"
      }
    ]
  }
}
```

### 6.2 メンバー追加

```http
POST /api/activities/{activity_id}/members
```

| 項目 | 型 | 必須 | 省略時 |
| --- | --- | --- | --- |
| `name` | string | はい | - |
| `group_name` | string / null | いいえ | `null` |
| `category` | string / null | いいえ | `null` |
| `note` | string | いいえ | 空文字 |

```json
{
  "name": "田中",
  "group_name": "企画班",
  "category": "2026年度",
  "note": "代表者"
}
```

成功時は `201 Created` で、`data.member` に作成したメンバーを返します。

`group_name` は画面上の「所属グループ」、`category` は「所属区分」に対応します。旧クライアントとの互換性のため、`group_name` がない場合は `part`、`category` がない場合は `generation` も入力として受け付けます。レスポンスは新しいキーだけを返します。

### 6.3 メンバー更新

```http
PUT /api/activities/{activity_id}/members/{member_id}
```

項目は追加時と同じです。部分更新ではないため、`name` は毎回必須です。省略した任意項目は上表の省略時の値に更新されます。

### 6.4 メンバー削除

```http
DELETE /api/activities/{activity_id}/members/{member_id}
```

`data.deleted_member` に削除したメンバーを返します。紐づく受付情報も削除されます。

## 7. 活動日API

### 7.1 活動日一覧取得

```http
GET /api/activities/{activity_id}/sessions
```

活動日の新しい順で返します。各要素には `id`、`session_date`、`title`、`place`、`note`、`created_at` が含まれます。

### 7.2 活動日追加

```http
POST /api/activities/{activity_id}/sessions
```

| 項目 | 型 | 必須 | 省略時 |
| --- | --- | --- | --- |
| `session_date` | string（`YYYY-MM-DD`） | はい | - |
| `title` | string | いいえ | `通常活動` |
| `place` | string | いいえ | 空文字 |
| `note` | string | いいえ | 空文字 |

```json
{
  "session_date": "2026-08-10",
  "title": "通常活動",
  "place": "練習室A",
  "note": "譜面台を持参"
}
```

成功時は `201 Created` で、`data.session` に作成した活動日を返します。

### 7.3 活動日更新

```http
PUT /api/activities/{activity_id}/sessions/{session_id}
```

項目は追加時と同じです。部分更新ではないため、`session_date` は毎回必須です。省略した任意項目は上表の省略時の値に更新されます。

### 7.4 活動日削除

```http
DELETE /api/activities/{activity_id}/sessions/{session_id}
```

`data.deleted_session` に削除した活動日を返します。紐づく受付情報も削除されます。

## 8. 受付API

### 8.1 受付一覧取得

```http
GET /api/activities/{activity_id}/sessions/{session_id}/attendance
```

対象活動日の受付一覧と件数を返します。このGETリクエストには副作用があり、受付レコードがまだないメンバーについて、`unchecked` 状態のレコードを自動作成します。

```json
{
  "success": true,
  "message": "受付一覧を取得しました。",
  "data": {
    "activity": {
      "id": 2,
      "name": "オーケストラ"
    },
    "session": {
      "id": 1,
      "session_date": "Mon, 10 Aug 2026 00:00:00 GMT",
      "title": "通常活動",
      "place": "練習室A",
      "note": ""
    },
    "counts": {
      "total_count": 2,
      "checked_count": 1,
      "unchecked_count": 1
    },
    "attendances": [
      {
        "id": 10,
        "status": "checked",
        "checked_in_at": "Sat, 11 Jul 2026 04:30:00 GMT",
        "note": "",
        "member_id": 1,
        "name": "田中",
        "group_name": "企画班",
        "category": "2026年度"
      }
    ]
  }
}
```

### 8.2 受付済みにする

```http
POST /api/activities/{activity_id}/attendance/{attendance_id}/check_in
```

リクエストボディは不要です。`status` を `checked` にし、`checked_in_at` をサーバーの現在時刻で更新します。すでに受付済みの場合も受付時刻は更新されます。

### 8.3 未受付に戻す

```http
POST /api/activities/{activity_id}/attendance/{attendance_id}/cancel_check_in
```

リクエストボディは不要です。`status` を `unchecked` にし、`checked_in_at` を `null` にします。

### 8.4 受付備考更新

```http
PUT /api/activities/{activity_id}/attendance/{attendance_id}/note
```

`note` は任意の文字列です。省略すると空文字に更新されます。

```json
{
  "note": "遅刻連絡あり"
}
```

受付の更新APIは、`data.attendance` に `id`、`session_id`、`member_id`、`status`、`checked_in_at`、`note` を返します。

## 9. 集計API

### 9.1 個人別出席率取得

```http
GET /api/activities/{activity_id}/attendance/summary
```

```json
{
  "success": true,
  "message": "個人別出席率を取得しました。",
  "data": {
    "activity": {
      "id": 2,
      "name": "オーケストラ"
    },
    "summaries": [
      {
        "member_id": 1,
        "name": "田中",
        "group_name": "企画班",
        "category": "2026年度",
        "total_count": 3,
        "checked_count": 2,
        "attendance_rate": 66.7
      }
    ]
  }
}
```

### 9.2 所属グループ・所属区分別出席率取得

```http
GET /api/activities/{activity_id}/attendance/group_summary
```

```json
{
  "success": true,
  "message": "所属グループ・所属区分別出席率を取得しました。",
  "data": {
    "activity": {
      "id": 2,
      "name": "オーケストラ"
    },
    "group_name_summaries": [
      {
        "group_name": "企画班",
        "total_count": 3,
        "checked_count": 2,
        "attendance_rate": 66.7
      }
    ],
    "category_summaries": [
      {
        "category": "2026年度",
        "total_count": 3,
        "checked_count": 2,
        "attendance_rate": 66.7
      }
    ]
  }
}
```

`attendance_rate` は `checked_count / total_count * 100` を小数第1位に丸めた値です。受付レコードがない場合は `0` です。集計の母数は、受付一覧を開くなどして受付レコードが作成された活動日数です。

## 10. 利用例

### curl

```bash
# ログイン
curl -X POST http://127.0.0.1:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# 活動一覧（TOKENはログインレスポンスのdata.token）
curl http://127.0.0.1:5000/api/activities \
  -H "Authorization: Bearer TOKEN"

# 活動作成
curl -X POST http://127.0.0.1:5000/api/activities \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"オーケストラ","description":"定期練習"}'
```

### PowerShell

```powershell
$baseUrl = "http://127.0.0.1:5000"
$loginBody = @{ username = "admin"; password = "password" } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/login" -ContentType "application/json" -Body $loginBody
$headers = @{ Authorization = "Bearer $($login.data.token)" }

Invoke-RestMethod -Method Get -Uri "$baseUrl/api/activities" -Headers $headers

$activityBody = @{ name = "オーケストラ"; description = "定期練習" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$baseUrl/api/activities" -Headers $headers -ContentType "application/json" -Body $activityBody
```

## 11. Web画面にはあるがAPIにはない機能

- 活動日の一括追加
- 受付状況のCSV出力
- ユーザー作成・パスワード変更
