package models

import "time"

// RefreshToken 刷新令牌。
//
// 为什么不把 refresh 也做成 JWT：JWT 自包含、服务端不留状态，所以「让这个 token
// 立刻失效」在数学上做不到。而登出和改密码后强制下线都必须能吊销。
// 把吊销需求全部压到这张有状态的表上，access token 才能保持无状态
//（见《认证中心设计文档》§4.2）
//
// 表名带 auth_ 前缀：本表与 call-back 共库，前缀让「谁拥有哪张表」一目了然
type RefreshToken struct {
	ID     uint `gorm:"primaryKey"`
	UserID uint `gorm:"index;not null"`

	// TokenHash sha256(明文)。**绝不存明文**：数据库泄露时攻击者拿到的
	// hash 不能直接用来登录
	TokenHash string `gorm:"size:64;uniqueIndex;not null"`

	// ClientID 这个 token 发给哪个应用了。现在只用于审计，
	// 以后做「管理已登录设备」直接就有数据
	ClientID string `gorm:"size:64;index"`

	ExpiresAt time.Time `gorm:"index;not null"`

	// UsedAt 已轮换过的时间。**再次收到同一个 token 就是重放信号**，
	// 处理方式见 services 里的轮换逻辑
	UsedAt *time.Time

	// RevokedAt 主动吊销的时间（登出、改密码、检测到重放）
	RevokedAt *time.Time

	CreatedAt time.Time
}

func (RefreshToken) TableName() string {
	return "auth_refresh_tokens"
}

// IsUsable 这个 token 现在还能用来换 access token 吗
func (t *RefreshToken) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// WasRotated 是否已经轮换过。用于区分「过期/吊销」和「重放」——
// 前者是正常情况，后者要按疑似泄露处理
func (t *RefreshToken) WasRotated() bool {
	return t.UsedAt != nil
}
