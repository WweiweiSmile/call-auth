// 自验证脚本。
//
// 它站在**一个资源服务**（call-back / learn-daily）的立场上跑完整条链路：
// 只从 JWKS 取公钥、绝不接触私钥，然后独立验证 token 的签名和各项声明。
//
// 这正是在证明整个方案的核心性质 —— 签发权只归认证中心，其他服务拿公钥
// 只能验、不能签（《认证中心设计文档》§3.2）。
//
//	cd call-auth
//	go run ./scripts/verify
//	BASE=http://localhost:8020 go run ./scripts/verify
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

var baseURL = envOr("BASE", "http://localhost:8020")

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	passed int
	failed int
)

func check(name string, ok bool, detail string) {
	if ok {
		passed++
		fmt.Printf("  \033[32m✓\033[0m %s\n", name)
		return
	}
	failed++
	fmt.Printf("  \033[31m✗\033[0m %s\n", name)
	if detail != "" {
		fmt.Printf("      %s\n", detail)
	}
}

type envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Error   string          `json:"error"`
	Data    json.RawMessage `json:"data"`
}

type tokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	User         struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

func post(path string, body any, bearer string) (int, envelope) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(req)
}

func get(path, bearer string) (int, envelope) {
	req, _ := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(req)
}

func do(req *http.Request) (int, envelope) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("\n\033[31m连不上 %s：%v\033[0m\n", baseURL, err)
		fmt.Println("先启动服务：go run .")
		os.Exit(1)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var env envelope
	// JWKS 不带信封，直接是 {"keys":[...]}，这里解不出来也没关系，
	// 调用方会自己再解一次原始 body
	_ = json.Unmarshal(raw, &env)
	if env.Data == nil {
		env.Data = raw
	}
	return resp.StatusCode, env
}

func main() {
	fmt.Printf("目标：%s\n\n", baseURL)

	fmt.Println("【1】服务可用性")
	status, _ := get("/health", "")
	check("GET /health 返回 200", status == 200, fmt.Sprintf("实际 %d", status))

	fmt.Println("\n【2】JWKS 公钥集")
	status, _ = get("/.well-known/jwks.json", "")
	check("无需认证即可获取", status == 200, fmt.Sprintf("实际 %d", status))

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	_, env := get("/.well-known/jwks.json", "")
	_ = json.Unmarshal(env.Data, &jwks)

	if len(jwks.Keys) == 0 {
		check("至少暴露一把公钥", false, "keys 为空")
		summary()
		return
	}
	key := jwks.Keys[0]
	check("至少暴露一把公钥", true, "")
	check("字段齐全", key["kty"] == "RSA" && key["alg"] == "RS256" && key["kid"] != "",
		fmt.Sprintf("kty=%s alg=%s kid=%s", key["kty"], key["alg"], key["kid"]))

	pub, err := publicKeyFromJWKS(key["n"], key["e"])
	check("n/e 能还原成 RSA 公钥", err == nil, fmt.Sprint(err))
	if err != nil {
		summary()
		return
	}
	// 这一步很关键：我们**只用公钥**。私钥从没离开过认证中心
	fmt.Println("      （以下验签只用公钥，私钥从未离开认证中心）")

	fmt.Println("\n【3】注册与登录")
	username := fmt.Sprintf("verify_%d", time.Now().Unix())
	status, env = post("/api/v1/auth/register", map[string]string{
		"username": username, "password": "verify-password-123", "nickname": "自验证",
	}, "")
	check("注册返回 200", status == 200, fmt.Sprintf("实际 %d: %s", status, env.Message))

	var registered tokenData
	_ = json.Unmarshal(env.Data, &registered)
	check("注册直接返回登录态", registered.AccessToken != "" && registered.RefreshToken != "",
		"注册后不该还要再登一次")
	check("新用户角色是 user", registered.User.Role == "user",
		fmt.Sprintf("实际 %q —— 不能有隐式提权", registered.User.Role))

	status, env = post("/api/v1/auth/login", map[string]string{
		"username": username, "password": "verify-password-123", "client_id": "verify-script",
	}, "")
	check("登录返回 200", status == 200, fmt.Sprintf("实际 %d: %s", status, env.Message))

	var session tokenData
	_ = json.Unmarshal(env.Data, &session)
	check("返回 access + refresh", session.AccessToken != "" && session.RefreshToken != "", "")
	check("expires_in 是 15 分钟", session.ExpiresIn == 900, fmt.Sprintf("实际 %d", session.ExpiresIn))

	fmt.Println("\n【4】用公钥独立验签（模拟资源服务）")
	claims, err := verifyWithPublicKey(pub, session.AccessToken)
	check("签名验证通过", err == nil, fmt.Sprint(err))
	if err == nil {
		check("sub 是用户 id", claims["sub"] == fmt.Sprint(session.User.ID),
			fmt.Sprintf("sub=%v 期望=%d", claims["sub"], session.User.ID))
		check("iss 是 call-auth", claims["iss"] == "call-auth", fmt.Sprint(claims["iss"]))
		check("带 exp", claims["exp"] != nil, "没有 exp 的 token 等于永不过期")
		check("带 jti", claims["jti"] != nil, "将来做黑名单需要它")
		if exp, ok := claims["exp"].(float64); ok {
			left := time.Until(time.Unix(int64(exp), 0))
			check("有效期约 15 分钟", left > 13*time.Minute && left <= 15*time.Minute,
				fmt.Sprintf("剩余 %v", left.Round(time.Second)))
		}
	}

	fmt.Println("\n【5】篡改会被发现")
	tampered := tamper(session.AccessToken)
	_, err = verifyWithPublicKey(pub, tampered)
	check("改过 payload 的 token 验签失败", err != nil, "篡改竟然通过了")

	fmt.Println("\n【6】受保护端点")
	status, env = get("/api/v1/auth/me", session.AccessToken)
	check("带 token 能取到自己的信息", status == 200, fmt.Sprintf("实际 %d: %s", status, env.Message))

	status, _ = get("/api/v1/auth/me", "")
	check("不带 token 返回 401", status == 401, fmt.Sprintf("实际 %d", status))

	status, _ = get("/api/v1/auth/me", "garbage.token.here")
	check("垃圾 token 返回 401", status == 401, fmt.Sprintf("实际 %d", status))

	fmt.Println("\n【7】轮换与重放检测")
	status, env = post("/api/v1/auth/refresh", map[string]string{
		"refresh_token": session.RefreshToken,
	}, "")
	check("refresh 返回 200", status == 200, fmt.Sprintf("实际 %d: %s", status, env.Message))

	var rotated tokenData
	_ = json.Unmarshal(env.Data, &rotated)
	check("轮换后 refresh token 变了", rotated.RefreshToken != session.RefreshToken,
		"轮换的意义就是换一个新的")

	// 再用一次旧的 —— 这是重放
	status, env = post("/api/v1/auth/refresh", map[string]string{
		"refresh_token": session.RefreshToken,
	}, "")
	check("重放旧 token 被拒绝", status == 401, fmt.Sprintf("实际 %d", status))
	check("错误标识是 token_reuse_detected", env.Error == "token_reuse_detected",
		fmt.Sprintf("实际 %q", env.Error))

	// 检测到重放后，连新的也一起吊销 —— 不能假设攻击者手上是哪一个
	status, _ = post("/api/v1/auth/refresh", map[string]string{
		"refresh_token": rotated.RefreshToken,
	}, "")
	check("重放后连新 token 也失效（全量吊销）", status == 401,
		fmt.Sprintf("实际 %d —— 检测到泄露时必须全量清理", status))

	fmt.Println("\n【8】登出")
	status, env = post("/api/v1/auth/login", map[string]string{
		"username": username, "password": "verify-password-123",
	}, "")
	var fresh tokenData
	_ = json.Unmarshal(env.Data, &fresh)

	status, _ = post("/api/v1/auth/logout", map[string]string{
		"refresh_token": fresh.RefreshToken,
	}, "")
	check("登出返回 200", status == 200, fmt.Sprintf("实际 %d", status))

	status, env = post("/api/v1/auth/refresh", map[string]string{
		"refresh_token": fresh.RefreshToken,
	}, "")
	check("登出后 refresh 失效", status == 401, fmt.Sprintf("实际 %d", status))
	// 登出是"正常死亡"，不能报成重放 —— 那会连带吊销该用户其他设备
	check("登出后报的是 token_invalid 而不是 reuse", env.Error == "token_invalid",
		fmt.Sprintf("实际 %q", env.Error))

	fmt.Println("\n【9】错误处理")
	status, env = post("/api/v1/auth/login", map[string]string{
		"username": username, "password": "wrong-password",
	}, "")
	check("密码错返回 401", status == 401, fmt.Sprintf("实际 %d", status))

	status2, env2 := post("/api/v1/auth/login", map[string]string{
		"username": "definitely_not_exists_12345", "password": "wrong-password",
	}, "")
	check("不存在的用户也是 401", status2 == 401, fmt.Sprintf("实际 %d", status2))
	check("两种失败的文案一致（防用户名枚举）", env.Message == env2.Message,
		fmt.Sprintf("%q vs %q", env.Message, env2.Message))

	status, env = post("/api/v1/auth/register", map[string]string{
		"username": username, "password": "verify-password-123",
	}, "")
	check("重复用户名返回 409", status == 409, fmt.Sprintf("实际 %d", status))

	status, _ = post("/api/v1/auth/register", map[string]string{
		"username": "abc", "password": "short",
	}, "")
	check("弱密码返回 400", status == 400, fmt.Sprintf("实际 %d", status))

	summary()
}

// verifyWithPublicKey 只用公钥验签。这正是 call-back / learn-daily 将来要做的事
func verifyWithPublicKey(pub *rsa.PublicKey, tokenString string) (map[string]any, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("意外的签名算法: %v", t.Header["alg"])
		}
		return pub, nil
	},
		jwt.WithIssuer("call-auth"),
		jwt.WithAudience("call-back"),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(60*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func publicKeyFromJWKS(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("解 n 失败: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("解 e 失败: %w", err)
	}

	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("指数 e 为 0")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// tamper 翻转 payload 段的一个字符，模拟被篡改的 token
func tamper(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}
	payload := []byte(parts[1])
	if payload[0] == 'A' {
		payload[0] = 'B'
	} else {
		payload[0] = 'A'
	}
	parts[1] = string(payload)
	return strings.Join(parts, ".")
}

func summary() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 46))
	if failed == 0 {
		fmt.Printf("\033[32m全部通过：%d 项\033[0m\n", passed)
	} else {
		fmt.Printf("\033[31m失败 %d 项\033[0m，通过 %d 项\n", failed, passed)
		os.Exit(1)
	}
}
