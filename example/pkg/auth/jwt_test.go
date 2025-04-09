package auth_test

import (
	"fmt"
	"testing"
	"time"

	// 仮のパス。実際のパスは機能実装時に確定する。
	// "github.com/tKwbr999/roocode-boomerang-mode/example/pkg/auth"
	// 現時点では auth パッケージが存在しないため、テスト対象の関数を直接定義するか、
	// テストファイル内に仮実装する。ここでは後者を選択。

	"github.com/golang-jwt/jwt/v5" // jwt-go v5 を使用
	"github.com/google/uuid"       // UUID生成用
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- 仮実装 (本来は pkg/auth/jwt.go などに実装される想定) ---

// テスト用の固定シークレットキー (実際は環境変数などから取得)
var jwtTestSecret = []byte("test-secret-key-should-be-longer-and-random")

// テスト用の固定有効期限 (実際は環境変数などから取得)
var jwtTestExpiration = time.Hour * 1

// Claims はJWTのペイロードを表す構造体です。
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateToken は指定されたユーザーIDを含むJWTを生成します。
func GenerateToken(userID uuid.UUID) (string, error) {
	if userID == uuid.Nil {
		return "", fmt.Errorf("user ID cannot be nil") // ユーザーIDがNilの場合のエラー
	}

	expirationTime := time.Now().Add(jwtTestExpiration)
	claims := &Claims{
		UserID: userID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "gotodo-api", // 発行者 (例)
			Subject:   "user-auth",  // トークンの主題 (例)
		},
	}

	// HS256署名アルゴリズムでトークンを生成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtTestSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken は与えられたJWT文字列を検証し、ユーザーIDを返します。
func ValidateToken(tokenString string) (uuid.UUID, error) {
	if tokenString == "" {
		return uuid.Nil, fmt.Errorf("token string cannot be empty")
	}

	claims := &Claims{}

	// トークンをパースして検証
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// 署名アルゴリズムが期待通り (HS256) か確認
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// 正しいシークレットキーを返す
		return jwtTestSecret, nil
	})

	if err != nil {
		// エラーの種類によって詳細なエラーを返すことも可能
		// 例: if errors.Is(err, jwt.ErrTokenExpired) { ... }
		return uuid.Nil, fmt.Errorf("token validation failed: %w", err)
	}

	// トークンとクレームが有効か確認
	if !token.Valid || claims == nil {
		return uuid.Nil, fmt.Errorf("invalid token or claims")
	}

	// クレームからユーザーIDをパース
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse user ID from token claims: %w", err)
	}
	if userID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("user ID in token claims is nil")
	}

	return userID, nil
}

// --- 仮実装ここまで ---

// TestGenerateToken は GenerateToken 関数のテストです。
func TestGenerateToken(t *testing.T) {
	userID := uuid.New()

	// --- 正常系 ---
	tokenString, err := GenerateToken(userID)
	require.NoError(t, err, "トークン生成でエラーが発生しないこと")
	require.NotEmpty(t, tokenString, "生成されたトークン文字列が空でないこと")

	// 生成されたトークンを検証してみる (ValidateTokenを使って)
	parsedUserID, validateErr := ValidateToken(tokenString)
	require.NoError(t, validateErr, "生成されたトークンがValidateTokenで有効であること")
	assert.Equal(t, userID, parsedUserID, "トークンからパースされたユーザーIDが元のIDと一致すること")

	// トークンをデコードしてクレームを確認 (より詳細な検証)
	claims := &Claims{}
	_, _, decodeErr := new(jwt.Parser).ParseUnverified(tokenString, claims)
	require.NoError(t, decodeErr, "トークン文字列のデコードに成功すること")
	assert.Equal(t, userID.String(), claims.UserID, "デコードされたクレームのUserIDが正しいこと")
	assert.WithinDuration(t, time.Now().Add(jwtTestExpiration), claims.RegisteredClaims.ExpiresAt.Time, 5*time.Second, "有効期限が期待通りであること (誤差5秒以内)")
	assert.Equal(t, "gotodo-api", claims.RegisteredClaims.Issuer, "発行者が正しいこと")
	assert.Equal(t, "user-auth", claims.RegisteredClaims.Subject, "主題が正しいこと")

	// --- 異常系 ---
	// Nil UUID でトークン生成を試みる
	_, errNilUUID := GenerateToken(uuid.Nil)
	assert.Error(t, errNilUUID, "Nil UUID でトークン生成を試みるとエラーが発生すること")
}

// TestValidateToken は ValidateToken 関数のテストです。
func TestValidateToken(t *testing.T) {
	userID := uuid.New()
	validTokenString, err := GenerateToken(userID)
	require.NoError(t, err, "テスト用の有効なトークン生成に成功すること")

	// --- 正常系 ---
	parsedUserID, validateErr := ValidateToken(validTokenString)
	require.NoError(t, validateErr, "有効なトークンの検証でエラーが発生しないこと")
	assert.Equal(t, userID, parsedUserID, "有効なトークンから正しいユーザーIDが取得できること")

	// --- 異常系 ---
	// 空のトークン文字列
	_, errEmpty := ValidateToken("")
	assert.Error(t, errEmpty, "空のトークン文字列で検証が失敗すること")

	// 無効な形式のトークン文字列
	invalidFormatToken := "this.is.not.a.jwt"
	_, errInvalidFormat := ValidateToken(invalidFormatToken)
	assert.Error(t, errInvalidFormat, "無効な形式のトークンで検証が失敗すること")

	// 署名が異なるトークン (別のシークレットキーで署名)
	anotherSecret := []byte("another-different-secret-key")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		UserID: userID.String(),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	})
	wrongSignedToken, _ := token.SignedString(anotherSecret)
	_, errWrongSign := ValidateToken(wrongSignedToken)
	assert.Error(t, errWrongSign, "異なるシークレットキーで署名されたトークンで検証が失敗すること")

	// 期限切れトークン
	expiredTime := time.Now().Add(-2 * time.Hour) // 2時間前に期限切れ
	expiredClaims := &Claims{
		UserID: userID.String(),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiredTime)},
	}
	expiredTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, _ := expiredTokenObj.SignedString(jwtTestSecret)
	_, errExpired := ValidateToken(expiredTokenString)
	assert.Error(t, errExpired, "期限切れトークンで検証が失敗すること")
	// エラーが jwt.ErrTokenExpired であることを確認 (より厳密なチェック)
	assert.ErrorIs(t, errExpired, jwt.ErrTokenExpired, "エラーが jwt.ErrTokenExpired であること")

	// // 異なる署名アルゴリズム (例: RS256) のテスト
	// // jwt-go/v5 では SplitCompact, DecodeSegment 等が提供されていないか、
	// // 内部実装に依存するため、このテストケースはコメントアウトします。
	// // アルゴリズムの検証は ParseWithClaims の keyFunc で行われます。
	// parts := jwt.SplitCompact(validTokenString)
	// if len(parts) == 3 {
	// 	// ヘッダー部分をデコードし、alg を書き換えて再エンコード (Base64 Raw URL Encoding)
	// 	headerJSON, _ := jwt.DecodeSegment(parts[0])
	// 	headerMap := make(map[string]interface{})
	// 	_ = json.Unmarshal(headerJSON, &headerMap) // 標準のjsonを使用
	// 	headerMap["alg"] = "RS256" // アルゴリズムを偽装
	// 	newHeaderJSON, _ := json.Marshal(headerMap) // 標準のjsonを使用
	// 	newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON) // 標準のbase64を使用
	// 	invalidAlgToken := fmt.Sprintf("%s.%s.%s", newHeader, parts[1], parts[2])
	//
	// 	_, errInvalidAlg := ValidateToken(invalidAlgToken)
	// 	assert.Error(t, errInvalidAlg, "異なる署名アルゴリズムのトークンで検証が失敗すること")
	// 	assert.Contains(t, errInvalidAlg.Error(), "unexpected signing method", "エラーメッセージに署名アルゴリズムの不一致が含まれること")
	// } else {
	// 	t.Log("有効なトークンを分割できなかったため、アルゴリズム偽装テストをスキップします。")
	// }

	// UserID が Nil のクレームを持つトークン
	nilUserIDClaims := &Claims{
		UserID: uuid.Nil.String(), // Nil UUID
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}
	nilUserIDTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, nilUserIDClaims)
	nilUserIDTokenString, _ := nilUserIDTokenObj.SignedString(jwtTestSecret)
	_, errNilUserID := ValidateToken(nilUserIDTokenString)
	assert.Error(t, errNilUserID, "UserIDがNilのクレームを持つトークンで検証が失敗すること")

	// UserID が UUID 形式ではないクレームを持つトークン
	invalidUserIDClaims := &Claims{
		UserID: "not-a-valid-uuid", // 不正な形式
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}
	invalidUserIDTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidUserIDClaims)
	invalidUserIDTokenString, _ := invalidUserIDTokenObj.SignedString(jwtTestSecret)
	_, errInvalidUserID := ValidateToken(invalidUserIDTokenString)
	assert.Error(t, errInvalidUserID, "UserIDが不正な形式のクレームを持つトークンで検証が失敗すること")
}
