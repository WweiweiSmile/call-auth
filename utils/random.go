package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// tokenBytes refresh token 的熵。32 字节 = 256 位，暴力猜解不可行
const tokenBytes = 32

// NewTokenID 生成 jti（JWT 的唯一标识）。16 字节足够，
// 它只需要在同一天内不重复，不需要抗猜测
func NewTokenID() string {
	return hex.EncodeToString(randomBytes(16))
}

// NewOpaqueToken 生成一个不透明的 refresh token。
//
// 返回（明文，sha256 十六进制）。**明文只返回这一次**，库里存的是 hash：
// 数据库泄露时攻击者拿到的 hash 不能直接用来登录。
//
// 为什么用 sha256 而不是 bcrypt：refresh token 是 256 位的高熵随机串，
// 不存在"弱口令"问题，而每次 refresh 都要查一次库，bcrypt 太慢。
// bcrypt 是给低熵的人类密码用的
func NewOpaqueToken() (plain string, hash string) {
	plain = hex.EncodeToString(randomBytes(tokenBytes))
	return plain, HashToken(plain)
}

// HashToken 算 token 的存储形式
func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// randomBytes 读 n 个密码学安全的随机字节。
//
// 不用 math/rand：它的输出可预测，用来生成 token 等于没有 token。
// crypto/rand.Read 自 Go 1.24 起保证不返回错误（内部失败会直接 panic），
// 所以这里不处理 error
func randomBytes(n int) []byte {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return buf
}
