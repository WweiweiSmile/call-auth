package utils

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "call-auth"
	testAudience = "call-back"
)

func newTestPair(t *testing.T) *KeyPair {
	t.Helper()
	pair, err := LoadOrCreateKeyPair(filepath.Join(t.TempDir(), "private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func signTest(t *testing.T, pair *KeyPair, ttl time.Duration) string {
	t.Helper()
	token, err := SignAccessToken(pair, 42, "weiweigod", "user", SignOptions{
		Issuer:    testIssuer,
		Audiences: []string{testAudience, "learn-daily"},
		TTL:       ttl,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func verifyTest(t *testing.T, pair *KeyPair, token string) (*AccessClaims, error) {
	t.Helper()
	return VerifyAccessToken(pair, token, VerifyOptions{
		Issuer:   testIssuer,
		Audience: testAudience,
		Leeway:   0,
	})
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pair := newTestPair(t)
	claims, err := verifyTest(t, pair, signTest(t, pair, time.Hour))
	if err != nil {
		t.Fatalf("正常 token 应验签通过: %v", err)
	}

	if claims.Username != "weiweigod" || claims.Role != "user" {
		t.Errorf("claims 不对: %+v", claims)
	}
	userID, err := claims.UserID()
	if err != nil {
		t.Fatalf("sub 应能转回用户 id: %v", err)
	}
	if userID != 42 {
		t.Errorf("用户 id 应为 42，实际 %d", userID)
	}
	// jti 现在不用，但将来做黑名单必须有它，所以签发时就得带上
	if claims.ID == "" {
		t.Error("token 应带 jti")
	}
}

func TestSubjectIsString(t *testing.T) {
	pair := newTestPair(t)
	raw, err := jwt.Parse(signTest(t, pair, time.Hour), func(*jwt.Token) (interface{}, error) {
		return &pair.Private.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// RFC 7519 要求 sub 是字符串。放 int 的话，校验严格的库会直接拒收
	if _, ok := raw.Claims.(jwt.MapClaims)["sub"].(string); !ok {
		t.Errorf("sub 必须是字符串，实际 %T", raw.Claims.(jwt.MapClaims)["sub"])
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	pair := newTestPair(t)
	// TTL 为负 => exp 在过去
	token := signTest(t, pair, -2*time.Minute)

	// leeway 设为 0，确保测的是过期本身而不是被容忍掉
	if _, err := verifyTest(t, pair, token); err == nil {
		t.Fatal("过期 token 必须被拒绝")
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	pair := newTestPair(t)
	token, err := SignAccessToken(pair, 1, "u", "user", SignOptions{
		Issuer: "somebody-else", Audiences: []string{testAudience}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTest(t, pair, token); err == nil {
		t.Fatal("issuer 不匹配必须被拒绝，否则别处签的 token 也能用")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	pair := newTestPair(t)
	// 只签给 learn-daily，call-back 不该认
	token, err := SignAccessToken(pair, 1, "u", "user", SignOptions{
		Issuer: testIssuer, Audiences: []string{"learn-daily"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTest(t, pair, token); err == nil {
		t.Fatal("aud 里没有本服务时必须拒绝，否则给 A 签的 token 能拿去调 B")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pair := newTestPair(t)
	token := signTest(t, pair, time.Hour)

	// 改掉 payload 里的一个字符，签名就对不上了
	tampered := []byte(token)
	dot := -1
	for i := len(tampered) - 1; i >= 0; i-- {
		if tampered[i] == '.' {
			dot = i
			break
		}
	}
	if tampered[dot+1] == 'A' {
		tampered[dot+1] = 'B'
	} else {
		tampered[dot+1] = 'A'
	}

	if _, err := verifyTest(t, pair, string(tampered)); err == nil {
		t.Fatal("被篡改的 token 必须被拒绝")
	}
}

func TestVerifyRejectsTokenFromAnotherKey(t *testing.T) {
	ours := newTestPair(t)
	theirs := newTestPair(t)

	// 用别人的密钥签，但把 kid 改成我们的 —— 目的是绕过 kid 检查，
	// 逼着验签走到真正的 RSA 校验那一步
	token, err := SignAccessToken(theirs, 1, "attacker", "admin", SignOptions{
		Issuer: testIssuer, Audiences: []string{testAudience}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(token, &AccessClaims{})
	if err != nil {
		t.Fatal(err)
	}
	parsed.Header["kid"] = ours.Kid
	forged, err := parsed.SignedString(theirs.Private)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifyTest(t, ours, forged); err == nil {
		t.Fatal("别的密钥签的 token 必须被拒绝 —— 这是整个方案的核心保证")
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	pair := newTestPair(t)

	// alg=none 是最经典的 JWT 漏洞：把算法改成 none、去掉签名，
	// 不校验算法的实现会直接放行
	token := jwt.NewWithClaims(jwt.SigningMethodNone, AccessClaims{
		Username: "attacker",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   "1",
			Audience:  jwt.ClaimStrings{testAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifyTest(t, pair, unsigned); err == nil {
		t.Fatal("alg=none 的 token 必须被拒绝")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	pair := newTestPair(t)
	for _, bad := range []string{"", "not-a-token", "a.b.c", "....."} {
		if _, err := verifyTest(t, pair, bad); err == nil {
			t.Errorf("%q 不是合法 token，必须被拒绝", bad)
		}
	}
}

func TestUserIDRejectsNonNumericSubject(t *testing.T) {
	claims := &AccessClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "not-a-number"}}
	if _, err := claims.UserID(); err == nil {
		t.Fatal("sub 不是数字时必须报错，不能悄悄当成 0 号用户")
	}
}
