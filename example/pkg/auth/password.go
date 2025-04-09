package auth

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword は与えられたパスワードをbcryptでハッシュ化します。
// セキュリティのため、bcrypt.DefaultCost を使用します。
func HashPassword(password string) (string, error) {
	// パスワードが空でないことを確認 (オプションだが推奨)
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	// bcrypt.DefaultCost はハッシュ化の計算コストを指定します。
	// コストが高いほど安全ですが、計算時間も増加します。
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// エラー発生時は詳細なエラー情報をラップして返す
		return "", fmt.Errorf("failed to generate password hash: %w", err)
	}
	return string(bytes), nil
}

// CheckPasswordHash は与えられたパスワードがハッシュと一致するか検証します。
func CheckPasswordHash(password, hash string) bool {
	// ハッシュとパスワードを比較します。
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	// エラーがなければ (nil であれば) パスワードは一致しています。
	// エラーが発生した場合 (不一致、ハッシュ形式不正など) は false を返します。
	return err == nil
}
