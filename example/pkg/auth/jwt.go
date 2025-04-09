package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	// 設定管理ライブラリ (viperなど) を利用してシークレットキーや有効期限を外部から読み込むのが望ましい
	// import "github.com/spf13/viper"
)

// --- 定数 ---
// パッケージレベルの変数は削除し、関数引数で受け取るように変更

// jwtIssuer はJWTの発行者を示す文字列です。
const jwtIssuer = "gotodo-api"

// jwtSubject はJWTの主題を示す文字列です。
const jwtSubject = "user-auth"

// --- 構造体 ---

// Claims はJWTのペイロード (クレーム) を表す構造体です。
// jwt.RegisteredClaims を埋め込むことで、標準的なクレーム (exp, iat, nbf, iss, subなど) を利用できます。
type Claims struct {
	UserID string `json:"user_id"` // カスタムクレームとしてユーザーIDを追加
	jwt.RegisteredClaims
}

// --- 関数 ---

// GenerateToken は指定されたユーザーIDを含むJWT文字列を生成します。
// HS256アルゴリズムで署名されます。
func GenerateToken(userID uuid.UUID, secretKey []byte, expiration time.Duration) (string, error) { // 引数に secretKey と expiration を追加
	// ユーザーIDがNilでないことを確認
	if userID == uuid.Nil {
		return "", fmt.Errorf("user ID cannot be nil when generating token")
	}

	// 有効期限を設定
	expirationTime := time.Now().Add(expiration) // 引数の expiration を使用

	// クレームを作成
	claims := &Claims{
		UserID: userID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // 有効期限 (Unixタイムスタンプ)
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // 発行日時 (Unixタイムスタンプ)
			NotBefore: jwt.NewNumericDate(time.Now()),     // 有効開始日時 (Unixタイムスタンプ)
			Issuer:    jwtIssuer,                          // 発行者
			Subject:   jwtSubject,                         // 主題
		},
	}

	// HS256署名アルゴリズムで新しいトークンオブジェクトを作成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// シークレットキーでトークンに署名し、文字列として取得
	tokenString, err := token.SignedString(secretKey) // 引数の secretKey を使用
	if err != nil {
		// 署名に失敗した場合のエラーハンドリング
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken は与えられたJWT文字列を検証し、埋め込まれたユーザーIDを返します。
// トークンの有効期限、署名、発行者、主題なども検証されます。
func ValidateToken(tokenString string, secretKey []byte) (uuid.UUID, error) { // 引数に secretKey を追加
	// トークン文字列が空でないことを確認
	if tokenString == "" {
		return uuid.Nil, fmt.Errorf("token string cannot be empty")
	}

	// パース結果を格納するためのClaims構造体のポインタを準備
	claims := &Claims{}

	// トークンをパースし、クレームを検証します。
	// jwt.ParseWithClaims は署名の検証、有効期限のチェックなども行います。
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// 署名アルゴリズムが期待通り (HS256) であることを確認します。
		// これにより、アルゴリズムダウングレード攻撃を防ぎます。
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// 正しいシークレットキーを返します。
		return secretKey, nil // 引数の secretKey を使用
	})

	// パースまたは検証中にエラーが発生した場合
	if err != nil {
		// エラーの種類に応じて詳細な情報を返すことも可能です。
		// 例: errors.Is(err, jwt.ErrTokenExpired) -> "token is expired"
		//     errors.Is(err, jwt.ErrTokenNotValidYet) -> "token not yet valid"
		//     errors.Is(err, jwt.ErrSignatureInvalid) -> "invalid signature"
		return uuid.Nil, fmt.Errorf("token validation failed: %w", err)
	}

	// トークン自体が無効、またはクレームが取得できなかった場合
	if !token.Valid || claims == nil {
		return uuid.Nil, fmt.Errorf("invalid token or claims")
	}

	// 標準クレームの検証 (発行者 Issuer, 主題 Subject) - オプションだが推奨
	// if !claims.VerifyIssuer(jwtIssuer, true) {
	// 	return uuid.Nil, fmt.Errorf("invalid token issuer: expected %s, got %s", jwtIssuer, claims.Issuer)
	// }
	// if !claims.VerifySubject(jwtSubject, true) { // Subjectの検証は用途に応じて
	//  return uuid.Nil, fmt.Errorf("invalid token subject")
	// }

	// カスタムクレームからユーザーIDをパース
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		// UserIDがUUIDとしてパースできない場合
		return uuid.Nil, fmt.Errorf("failed to parse user ID from token claims: %w", err)
	}
	// パースは成功したが、結果がNil UUIDだった場合 (通常はありえないが念のため)
	if userID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("user ID in token claims is nil")
	}

	// すべての検証をパスした場合、ユーザーIDを返す
	return userID, nil
}
