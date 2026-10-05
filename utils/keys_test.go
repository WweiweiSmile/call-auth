package utils

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func tempKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "keys", "private.pem")
}

func TestLoadOrCreateGeneratesWhenMissing(t *testing.T) {
	path := tempKeyPath(t)

	pair, err := LoadOrCreateKeyPair(path)
	if err != nil {
		t.Fatalf("首次加载应生成密钥而不是报错: %v", err)
	}
	if pair.Private == nil || pair.Kid == "" {
		t.Fatal("生成的密钥对不完整")
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("密钥应被写进 %s: %v", path, err)
	}
}

func TestGeneratedKeyFileIsOwnerOnly(t *testing.T) {
	path := tempKeyPath(t)
	if _, err := LoadOrCreateKeyPair(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// 私钥泄露等于整个签发体系被攻破，权限必须是 0600
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("私钥权限应为 0600，实际 %o", perm)
	}
}

func TestLoadReusesExistingKey(t *testing.T) {
	path := tempKeyPath(t)

	first, err := LoadOrCreateKeyPair(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateKeyPair(path)
	if err != nil {
		t.Fatal(err)
	}

	// kid 由公钥内容派生，所以重新读同一把密钥必须得到同一个 kid。
	// 不一致的话，服务重启后所有已发出的 token 都会因为 kid 对不上而被拒
	if first.Kid != second.Kid {
		t.Errorf("同一把密钥两次加载的 kid 应一致，%q != %q", first.Kid, second.Kid)
	}
	if !first.Private.Equal(second.Private) {
		t.Error("两次加载应得到同一把私钥")
	}
}

func TestKidIsStableForTheSameKey(t *testing.T) {
	pair, err := LoadOrCreateKeyPair(tempKeyPath(t))
	if err != nil {
		t.Fatal(err)
	}

	// 同一把密钥在任意机器上算出的 kid 都必须一样，
	// 否则轮换和缓存都会错乱
	again := newKeyPair(pair.Private)
	if again.Kid != pair.Kid {
		t.Errorf("同密钥两次派生的 kid 应一致：%q != %q", again.Kid, pair.Kid)
	}
	if len(pair.Kid) != 16 {
		t.Errorf("kid 长度应为 16，实际 %d", len(pair.Kid))
	}
}

func TestDifferentKeysGetDifferentKids(t *testing.T) {
	a, err := LoadOrCreateKeyPair(tempKeyPath(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateKeyPair(tempKeyPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if a.Kid == b.Kid {
		t.Error("不同的密钥必须有不同的 kid，否则轮换时验签方会选错公钥")
	}
}

func TestRejectsBrokenKeyFile(t *testing.T) {
	path := tempKeyPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("这不是 PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 文件存在但内容坏了必须报错，**不能**悄悄生成一把新的 ——
	// 那会让所有已发出的 token 无声无息地失效
	if _, err := LoadOrCreateKeyPair(path); err == nil {
		t.Fatal("私钥文件损坏时必须报错，不能偷偷换一把新密钥")
	}
}

func TestJWKSShape(t *testing.T) {
	pair, err := LoadOrCreateKeyPair(tempKeyPath(t))
	if err != nil {
		t.Fatal(err)
	}

	keys := pair.JWKS()
	if len(keys) != 1 {
		t.Fatalf("当前应只暴露一把公钥，实际 %d", len(keys))
	}

	entry := keys[0]
	for _, field := range []string{"kty", "use", "alg", "kid", "n", "e"} {
		if entry[field] == "" {
			t.Errorf("JWKS 缺少字段 %s", field)
		}
	}

	if entry["kty"] != "RSA" || entry["alg"] != "RS256" || entry["use"] != "sig" {
		t.Errorf("JWKS 头字段不对: %v", entry)
	}
	if entry["kid"] != pair.Kid {
		t.Errorf("JWKS 里的 kid 应与密钥一致：%q != %q", entry["kid"], pair.Kid)
	}

	// n 和 e 必须是 base64url **无填充**（RFC 7518 §6.3）。
	// 带 = 填充的话，各语言的 JWKS 客户端会解析失败
	for _, field := range []string{"n", "e"} {
		if _, err := base64.RawURLEncoding.DecodeString(entry[field]); err != nil {
			t.Errorf("%s 不是合法的 base64url 无填充: %v", field, err)
		}
	}
}
