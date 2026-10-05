package utils

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims 访问令牌的声明。字段设计见《认证中心设计文档》§7.1
type AccessClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// UserID 把 sub 转成用户 id。
//
// sub 按 JWT 规范必须是字符串（RFC 7519 的 StringOrURI），有些语言的库
// 放 int 进去会直接拒收。所以签发时转字符串，取出来再转回来
func (c *AccessClaims) UserID() (uint, error) {
	id, err := strconv.ParseUint(c.Subject, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("token 的 sub 不是合法的用户 id: %q", c.Subject)
	}
	return uint(id), nil
}

// SignOptions 签发参数
type SignOptions struct {
	Issuer    string
	Audiences []string
	TTL       time.Duration
}

// SignAccessToken 用私钥签发访问令牌。
//
// 只有认证中心调得到这个函数 —— 其他服务拿的是公钥，只能验不能签。
// 这是整个单点登录方案的支点（设计文档 §3.2）
func SignAccessToken(kp *KeyPair, userID uint, username, role string, opts SignOptions) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    opts.Issuer,
			Subject:   strconv.FormatUint(uint64(userID), 10),
			Audience:  jwt.ClaimStrings(opts.Audiences),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(opts.TTL)),
			// jti 现在用不上，但将来做黑名单/审计必须靠它。
			// 现在不加，以后就得改所有已经发出去的 token
			ID: NewTokenID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid 写进 header，验签方据此选公钥 —— 密钥轮换全靠它
	token.Header["kid"] = kp.Kid

	return token.SignedString(kp.Private)
}

// VerifyOptions 验签参数
type VerifyOptions struct {
	Issuer   string
	Audience string
	Leeway   time.Duration
}

// VerifyAccessToken 验签并返回声明
func VerifyAccessToken(kp *KeyPair, tokenString string, opts VerifyOptions) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessClaims{},
		func(t *jwt.Token) (interface{}, error) {
			// 显式锁死算法。不校验的话，攻击者可以把 header 里的 alg 改成
			// none 或换成别的算法，让验签形同虚设 —— JWT 最经典的漏洞
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("意外的签名算法: %v", t.Header["alg"])
			}
			// kid 对不上说明这个 token 是别的密钥签的。
			// 轮换期会同时存在多把密钥，那时这里要改成按 kid 查表
			if kid, ok := t.Header["kid"].(string); ok && kid != "" && kid != kp.Kid {
				return nil, fmt.Errorf("token 的 kid=%q 与本服务当前的 %q 不匹配", kid, kp.Kid)
			}
			return &kp.Private.PublicKey, nil
		},
		jwt.WithIssuer(opts.Issuer),
		// aud 必须包含本服务。没有这条，给 A 服务签的 token 能拿去调 B 服务
		jwt.WithAudience(opts.Audience),
		// 没有 exp 的 token 一律拒收
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(opts.Leeway),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, errors.New("token 无效")
	}
	return claims, nil
}
