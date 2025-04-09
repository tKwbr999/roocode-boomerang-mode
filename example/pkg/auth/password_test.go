package auth_test

import (
	"testing"

	// "golang.org/x/crypto/bcrypt" // bcrypt は auth パッケージ内で使用するため不要
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// 実装した auth パッケージをインポート
	"github.com/tKwbr999/roocode-boomerang-mode/example/pkg/auth"
)

// 仮実装は削除

// TestHashPassword は HashPassword 関数のテストです。
func TestHashPassword(t *testing.T) {
	password := "plainpassword123"

	// 1回目のハッシュ化
	hash1, err1 := auth.HashPassword(password) // auth. を追加
	require.NoError(t, err1, "パスワードのハッシュ化でエラーが発生しないこと")
	require.NotEmpty(t, hash1, "生成されたハッシュが空でないこと")

	// 2回目のハッシュ化
	hash2, err2 := auth.HashPassword(password) // auth. を追加
	require.NoError(t, err2, "再度パスワードをハッシュ化してもエラーが発生しないこと")
	require.NotEmpty(t, hash2, "2回目に生成されたハッシュが空でないこと")

	// 同じパスワードでも、ソルトが異なるため生成されるハッシュは毎回異なるはずです。
	assert.NotEqual(t, hash1, hash2, "同じパスワードから生成されたハッシュは異なること (ソルトのため)")

	// 生成されたハッシュが元のパスワードと一致するか、CheckPasswordHashを使って確認します。
	assert.True(t, auth.CheckPasswordHash(password, hash1), "生成されたハッシュ1でパスワード検証が成功すること") // auth. を追加
	assert.True(t, auth.CheckPasswordHash(password, hash2), "生成されたハッシュ2でパスワード検証が成功すること") // auth. を追加
}

// TestCheckPasswordHash は CheckPasswordHash 関数のテストです。
func TestCheckPasswordHash(t *testing.T) {
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	// テスト用のハッシュを生成
	hashedPassword, err := auth.HashPassword(password) // ここで err を := で宣言
	require.NoError(t, err, "テスト用ハッシュの生成でエラーが発生しないこと")
	require.NotEmpty(t, hashedPassword, "テスト用に生成されたハッシュが空でないこと")

	// --- 正常系 ---
	// 正しいパスワードで検証
	assert.True(t, auth.CheckPasswordHash(password, hashedPassword), "正しいパスワードで検証が成功すること") // auth. を追加

	// --- 異常系 ---
	// 間違ったパスワードで検証
	assert.False(t, auth.CheckPasswordHash(wrongPassword, hashedPassword), "間違ったパスワードで検証が失敗すること") // auth. を追加

	// 不正なハッシュ形式 (bcrypt形式ではない) で検証
	invalidHash := "thisisnotavalidbcryptHash"
	assert.False(t, auth.CheckPasswordHash(password, invalidHash), "不正な形式のハッシュで検証が失敗すること") // auth. を追加
// 空のパスワードに対する検証
emptyPassword := ""
// 空パスワードを HashPassword に渡すとエラーになることを期待する
// var err error // ここでの再宣言は不要
_, err = auth.HashPassword(emptyPassword) // 既に宣言済みの err に = で代入
require.Error(t, err, "空パスワードのハッシュ化でエラーが発生すること")
assert.Contains(t, err.Error(), "password cannot be empty", "エラーメッセージが期待通りであること")
// hashedEmptyPassword を使用するテストは不要なため削除
	// assert.False(t, auth.CheckPasswordHash("nonempty", hashedEmptyPassword), "空パスワードのハッシュに対して非空パスワードで検証が失敗すること") // hashedEmptyPassword が未定義のため削除

	// 空のハッシュに対する検証
	assert.False(t, auth.CheckPasswordHash(password, ""), "空のハッシュで検証が失敗すること") // auth. を追加
}
