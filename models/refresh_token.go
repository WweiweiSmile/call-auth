package models

import "time"

// RefreshToken 刷新令牌。
//
// 为什么不把 refresh 也做成 JWT：JWT 自包含、服务端不留状态，所以「让这个 token
// 立刻失效」在数学上做不到。而登出和改密码后强制下线都必须能吊销。
// 把吊销需求全部压到这张有状态的表上，access token 才能保持无状态
// （见《认证中心设计文档》§4.2）
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

	// Scope 这条记录是哪种登录态，取值见 ScopeApp / ScopeSSO。
	//
	// 必须区分，因为两者的生命周期和吊销语义完全不同：应用持有的登录态
	// 会随"登出"消失，而认证中心的浏览器会话不该被某个应用登出牵连
	//（否则在 A 应用登出会把 B 应用一起踢掉，见 §6.4）。
	// 旧行没有这一列，默认 app —— 语义与它们本来一致
	Scope string `gorm:"size:16;not null;default:'app';index"`

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

// 登录态的用途。同一张表装两种东西，复用同一套轮换与吊销逻辑（§5.2）
const (
	// ScopeApp 应用持有的登录态。会换出 access token，有效期 14 天
	ScopeApp = "app"

	// ScopeSSO 浏览器在认证中心域的会话 cookie。**不换 access token**，
	// 只用来在 /sso 换一次性票据；有效期 30 天（§6.2.1）
	ScopeSSO = "sso"
)

// IsUsable 这个 token 现在还能用来换 access token 吗
func (t *RefreshToken) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// WasRotated 是否已经轮换过。用于区分「过期/吊销」和「重放」——
// 前者是正常情况，后者要按疑似泄露处理
func (t *RefreshToken) WasRotated() bool {
	return t.UsedAt != nil
}
