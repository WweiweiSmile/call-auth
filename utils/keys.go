package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

// rsaKeyBits 2048 位。3072/4096 更安全但签发和验签都明显更慢，
// 而验签发生在**每个业务请求**上 —— 2048 在这个场景是合适的平衡点
const rsaKeyBits = 2048

// KeyPair 签名密钥对。整个认证中心只有它持私钥，其他服务只拿公钥（见 JWKS）
type KeyPair struct {
	Private *rsa.PrivateKey
	// Kid 密钥标识，出现在 JWT header 和 JWKS 里。
	// 轮换时靠它让验签方知道该用哪把公钥
	Kid string
}

// LoadOrCreateKeyPair 从 path 读私钥；文件不存在就**生成一把并写进去**。
//
// 自动生成是为了本地开发不用先跑一遍 openssl。但会大声记日志：
// 生产上如果看到「已生成新密钥」，说明路径配错了或者文件被删了 —— 那是要立刻
// 处理的事，因为换密钥意味着**所有已发出的 token 立刻全部失效**，所有人被登出。
func LoadOrCreateKeyPair(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parsePrivateKey(data)
	case os.IsNotExist(err):
		return generateAndStore(path)
	default:
		return nil, fmt.Errorf("读取私钥 %s 失败: %w", path, err)
	}
}

func parsePrivateKey(data []byte) (*KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("私钥文件不是合法的 PEM 格式")
	}

	// 先按 PKCS#1 试（openssl genrsa 的默认输出），再按 PKCS#8 试
	// （openssl genpkey 的输出）。两种都支持，省得部署时还要记得转换格式
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return newKeyPair(key), nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败（PKCS#1 与 PKCS#8 都不认）: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("私钥不是 RSA 类型，实际是 %T（本服务只支持 RS256）", parsed)
	}
	return newKeyPair(key), nil
}

func generateAndStore(path string) (*KeyPair, error) {
	log.Printf("Warning: 私钥 %s 不存在，正在生成一把新的。", path)
	log.Printf("Warning: 如果是生产环境，请确认路径没配错 —— 新密钥会让所有已发出的 token 立刻失效")

	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("生成 RSA 密钥失败: %w", err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("创建私钥目录 %s 失败: %w", dir, err)
		}
	}

	// 0600：只有属主能读写。这把文件泄露等于整个体系被攻破
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("写入私钥 %s 失败: %w", path, err)
	}
	defer file.Close()

	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if _, err := file.Write(encoded); err != nil {
		return nil, fmt.Errorf("写入私钥 %s 失败: %w", path, err)
	}

	pair := newKeyPair(key)
	log.Printf("已生成密钥对，kid=%s", pair.Kid)
	return pair, nil
}

// newKeyPair 由私钥算出密钥对。kid 由**公钥**内容派生，
// 所以同一把密钥在任何机器上算出的 kid 都一样，也不需要额外配置。
// 轮换时换了密钥，kid 自动就变了
func newKeyPair(key *rsa.PrivateKey) *KeyPair {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		// 公钥一定能序列化，走不到这里。真走到了说明 crypto 库出了问题
		panic(fmt.Sprintf("序列化公钥失败: %v", err))
	}
	sum := sha256.Sum256(der)
	return &KeyPair{Private: key, Kid: hex.EncodeToString(sum[:])[:16]}
}

// JWKS 返回标准 JWKS 文档的内容（不含外层包装）。
//
// 用标准格式而不是自定义一个 /publickey 端点，是为了白拿各语言 JWT 库的
// JWKS 客户端：它们会自己拉取、按 kid 缓存、后台刷新。自己写这套很容易出 bug。
func (kp *KeyPair) JWKS() []map[string]string {
	// e 通常是 65537，按大端字节表示是 AQAB
	e := big.NewInt(int64(kp.Private.PublicKey.E)).Bytes()

	return []map[string]string{
		{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kp.Kid,
			// n 和 e 都必须用 base64url **无填充**编码（RFC 7518 §6.3）
			"n": base64.RawURLEncoding.EncodeToString(kp.Private.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		},
	}
}
