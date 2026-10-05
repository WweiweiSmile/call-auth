package services

import (
	"log"
	"time"

	"call-auth/config"
	"call-auth/dto"
	"call-auth/models"
	"call-auth/utils"
)

// TokenService 令牌的签发、轮换与吊销。
//
// 它是**唯一**能签发 token 的地方 —— 其他服务拿的是公钥，只能验不能签。
// 这是整个单点登录方案的支点（设计文档 §3.2）
type TokenService struct {
	keys *utils.KeyPair
}

func NewTokenService(keys *utils.KeyPair) *TokenService {
	return &TokenService{keys: keys}
}

// Keys 供 JWKS 端点取公钥
func (s *TokenService) Keys() *utils.KeyPair {
	return s.keys
}

// Issue 签发一对新令牌。首次登录、注册、轮换走的都是它，
// 保证三种路径产出的令牌结构完全一致
func (s *TokenService) Issue(user *models.User, clientID string) (*dto.TokenResponse, error) {
	access, err := utils.SignAccessToken(s.keys, user.ID, user.Username, user.Role, utils.SignOptions{
		Issuer:    config.AppConfig.AuthIssuer,
		Audiences: config.AppConfig.AuthAudiences,
		TTL:       time.Duration(config.AppConfig.AccessTokenTTLSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	// 明文只在这里出现一次，随后落到响应体里；库里存的是 sha256
	plain, hash := utils.NewOpaqueToken()
	row := models.RefreshToken{
		UserID:    user.ID,
		TokenHash: hash,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(time.Duration(config.AppConfig.RefreshTokenTTLSeconds) * time.Second),
	}
	if err := config.DB.Create(&row).Error; err != nil {
		return nil, err
	}

	return &dto.TokenResponse{
		AccessToken:  access,
		RefreshToken: plain,
		ExpiresIn:    config.AppConfig.AccessTokenTTLSeconds,
		TokenType:    "Bearer",
		User:         ToUserInfo(user),
	}, nil
}

// Refresh 用 refresh token 换一对新令牌（轮换）。
func (s *TokenService) Refresh(plain string) (*dto.TokenResponse, error) {
	var row models.RefreshToken
	if err := config.DB.Where("token_hash = ?", utils.HashToken(plain)).First(&row).Error; err != nil {
		return nil, ErrTokenInvalid
	}

	now := time.Now()

	// 过期和已吊销是"正常死亡"，直接拒掉即可。
	// 这两项不会变，所以放在原子操作之前判断是安全的
	if row.RevokedAt != nil || now.After(row.ExpiresAt) {
		return nil, ErrTokenInvalid
	}

	// 用**条件更新**做原子的"占用"：只有 used_at 和 revoked_at 都为空时才写得进去。
	//
	// 为什么不先读后判断再写：那样有竞态 —— 两个并发请求可能都读到 used_at 为空、
	// 都通过判断，然后各自签发一对新令牌。而这个 token 本该是一次性的
	res := config.DB.Model(&models.RefreshToken{}).
		Where("id = ? AND used_at IS NULL AND revoked_at IS NULL", row.ID).
		Update("used_at", now)
	if res.Error != nil {
		return nil, res.Error
	}

	if res.RowsAffected == 0 {
		// 抢不到"占用"只有两种可能：
		//   1. 客户端并发或重试，同一个 token 提交了两次
		//   2. token 被偷了，攻击者拿着旧的来换
		//
		// 分不清是哪种，所以一律按最坏情况处理：吊销该用户全部登录态。
		// 宁可误伤（他重新登录一次），也不能放过真正的泄露 ——
		// 这是 OAuth2 refresh token rotation 的标准做法
		log.Printf("Warning: 检测到 refresh token 重放 user=%d，吊销其全部登录态", row.UserID)
		s.RevokeAll(row.UserID)
		return nil, ErrTokenReuse
	}

	var user models.User
	if err := config.DB.First(&user, row.UserID).Error; err != nil {
		return nil, ErrTokenInvalid
	}
	// 账号在登录之后被禁用了：拒绝续期，并顺手清掉残留的登录态。
	// 不清理的话，这个 refresh token 会一直活到过期
	if !user.IsActive() {
		s.RevokeAll(user.ID)
		return nil, ErrAccountDisabled
	}

	// 续期时沿用原来的 client_id，让"这个 token 属于哪个应用"这条线索不断
	return s.Issue(&user, row.ClientID)
}

// UserOf 由 refresh token 反查它属于谁。
//
// 登出走它：不要求带 access token（那个只有 15 分钟，过期后就登不出了），
// refresh token 本身就能定位到用户
func (s *TokenService) UserOf(plain string) (uint, error) {
	var row models.RefreshToken
	if err := config.DB.Where("token_hash = ?", utils.HashToken(plain)).First(&row).Error; err != nil {
		return 0, ErrTokenInvalid
	}
	return row.UserID, nil
}

// Logout 登出。
//
// plain 为空表示"登出所有设备"：吊销该用户的全部 refresh token。
// 注意登出**不影响** access token —— 它无状态，最长还能用到过期（15 分钟）。
// 这是本方案明确接受的窗口，见设计文档 §4.3
func (s *TokenService) Logout(userID uint, plain string) error {
	if plain == "" {
		s.RevokeAll(userID)
		return nil
	}
	return config.DB.Model(&models.RefreshToken{}).
		Where("user_id = ? AND token_hash = ? AND revoked_at IS NULL", userID, utils.HashToken(plain)).
		Update("revoked_at", time.Now()).Error
}

// RevokeAll 吊销某用户的全部登录态。登出所有设备、检测到重放、账号被禁用时调用
func (s *TokenService) RevokeAll(userID uint) {
	if err := config.DB.Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", time.Now()).Error; err != nil {
		log.Printf("Warning: 吊销 user=%d 的登录态失败: %v", userID, err)
	}
}

// Verify 验签 access token。给本服务的中间件用
func (s *TokenService) Verify(tokenString string) (*utils.AccessClaims, error) {
	return utils.VerifyAccessToken(s.keys, tokenString, utils.VerifyOptions{
		Issuer:   config.AppConfig.AuthIssuer,
		Audience: config.AppConfig.AuthIssuer, // 认证中心自己也在 aud 列表里
		Leeway:   time.Duration(config.AppConfig.LeewaySeconds) * time.Second,
	})
}
