package models

import "time"

// SSOTicket 一次性票据。
//
// 它是跨域传递登录态的**唯一**载体：应用 A 域下的 token 应用 B 读不到
// （localStorage / Taro storage 不跨域），所以由认证中心用一张 60 秒、
// 用过即焚的票据把登录态"递"过去。
//
// 相比把 token 直接塞 URL：票据泄露的窗口只有 60 秒且用过即废，
// token 则是长期有效（见 §4.5 的对比表）
type SSOTicket struct {
	ID uint `gorm:"primaryKey"`

	// TicketHash sha256(明文)。与 refresh token 同样的理由：库里不存明文，
	// 数据库泄露时拿到的 hash 不能直接用来兑换
	TicketHash string `gorm:"size:64;uniqueIndex;not null"`

	UserID   uint   `gorm:"index;not null"`
	ClientID string `gorm:"size:64;not null"`

	// RedirectURI 签发时确定的目标地址。兑换时会校验 client_id 与签发时一致，
	// 否则 A 应用能拿 B 应用的票据换 token（§6.8）
	RedirectURI string `gorm:"size:500;not null"`

	ExpiresAt time.Time `gorm:"index;not null"`

	// UsedAt 已兑换的时间。票据是一次性的，非空即作废
	UsedAt *time.Time

	CreatedAt time.Time
}

func (SSOTicket) TableName() string {
	return "sso_tickets"
}

// IsUsable 这张票现在还能兑换吗
func (t *SSOTicket) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && now.Before(t.ExpiresAt)
}
