package auth_test

import (
	"testing"

	"golang.org/x/crypto/bcrypt" // Go標準のbcrypt実装を利用

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- 仮実装 (本来は pkg/auth/password.go などに実装される想定) ---

// HashPassword は与えられたパスワードをbcryptでハッシュ化します。
func HashPassword(password string) (string, error) {
	// bcrypt.DefaultCost はハッシュ化の計算コストを指定します。
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err // エラーハンドリングを追加
	}
	return string(bytes), nil
}

// CheckPasswordHash は与えられたパスワードがハッシュと一致するか検証します。
func CheckPasswordHash(password, hash string) bool {
	// ハッシュとパスワードを比較します。
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	// エラーがなければ (nil であれば) パスワードは一致しています。
	return err == nil
}

// --- 仮実装ここまで ---

// TestHashPassword は HashPassword 関数のテストです。
func TestHashPassword(t *testing.T) {
	password := "plainpassword123"

	// 1回目のハッシュ化
	hash1, err1 := HashPassword(password)
	require.NoError(t, err1, "パスワードのハッシュ化でエラーが発生しないこと")
	require.NotEmpty(t, hash1, "生成されたハッシュが空でないこと")

	// 2回目のハッシュ化
	hash2, err2 := HashPassword(password)
	require.NoError(t, err2, "再度パスワードをハッシュ化してもエラーが発生しないこと")
	require.NotEmpty(t, hash2, "2回目に生成されたハッシュが空でないこと")

	// 同じパスワードでも、ソルトが異なるため生成されるハッシュは毎回異なるはずです。
	assert.NotEqual(t, hash1, hash2, "同じパスワードから生成されたハッシュは異なること (ソルトのため)")

	// 生成されたハッシュが元のパスワードと一致するか、CheckPasswordHashを使って確認します。
	assert.True(t, CheckPasswordHash(password, hash1), "生成されたハッシュ1でパスワード検証が成功すること")
	assert.True(t, CheckPasswordHash(password, hash2), "生成されたハッシュ2でパスワード検証が成功すること")
}

// TestCheckPasswordHash は CheckPasswordHash 関数のテストです。
func TestCheckPasswordHash(t *testing.T) {
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	// テスト用のハッシュを生成
	hashedPassword, err := HashPassword(password)
	require.NoError(t, err, "テスト用ハッシュの生成でエラーが発生しないこと")
	require.NotEmpty(t, hashedPassword, "テスト用に生成されたハッシュが空でないこと")

	// --- 正常系 ---
	// 正しいパスワードで検証
	assert.True(t, CheckPasswordHash(password, hashedPassword), "正しいパスワードで検証が成功すること")

	// --- 異常系 ---
	// 間違ったパスワードで検証
	assert.False(t, CheckPasswordHash(wrongPassword, hashedPassword), "間違ったパスワードで検証が失敗すること")

	// 不正なハッシュ形式 (bcrypt形式ではない) で検証
	invalidHash := "thisisnotavalidbcryptHash"
	assert.False(t, CheckPasswordHash(password, invalidHash), "不正な形式のハッシュで検証が失敗すること")

	// 空のパスワードに対する検証
	emptyPassword := ""
	hashedEmptyPassword, err := HashPassword(emptyPassword)
	require.NoError(t, err, "空パスワードのハッシュ化エラーなし")
	assert.True(t, CheckPasswordHash(emptyPassword, hashedEmptyPassword), "空パスワードとそのハッシュで検証が成功すること")
	assert.False(t, CheckPasswordHash("nonempty", hashedEmptyPassword), "空パスワードのハッシュに対して非空パスワードで検証が失敗すること")

	// 空のハッシュに対する検証
	assert.False(t, CheckPasswordHash(password, ""), "空のハッシュで検証が失敗すること")
}
