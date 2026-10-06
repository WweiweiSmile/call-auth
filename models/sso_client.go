package models

import (
	"encoding/json"
	"log"
	"time"
)

// SSOClient 应用注册表。
//
// **这张表是防开放重定向的关键**：/sso 只把票据发到表里登记过的 redirect_uri，
// 且必须**完全相等**才放行。前缀匹配可以用 `https://call.qwnet.top.evil.com`
// 绕过（见《认证中心设计文档》§4.5、§6.7）
type SSOClient struct {
	ClientID string `gorm:"size:64;primaryKey"`

	Name string `gorm:"size:100;not null"`

	// RedirectURIs JSON 数组。存 JSON 而不是逗号分隔，是因为 URL 里合法地
	// 存在逗号，用逗号当分隔符会有歧义
	RedirectURIs string `gorm:"type:text;not null"`

	// IsActive 停用的 client 会被 /sso 一律拒绝（和不存在同等对待，避免探测）
	//
	// ⚠️ GORM 的坑：这一列在库里有默认值 true，而 Create 会把**零值**（false）
	// 当成"没设"从而落回默认值 —— 也就是说 `Create(&SSOClient{IsActive: false})`
	// 建出来的其实是**启用**的。真要建一个停用的，得先建再 Update。
	// 现有调用点（seedSSOClients）一律建成启用，所以没踩到，但改种子数据时要当心
	IsActive  bool `gorm:"not null;default:true"`
	CreatedAt time.Time
}

func (SSOClient) TableName() string {
	return "sso_clients"
}

// AllowedRedirectURIs 解析登记的回调地址。
//
// 解析失败返回 nil（而不是半个列表）：配置坏掉的 client 应该彻底不可用，
// 而不是"碰巧还能匹配上一部分"
func (c *SSOClient) AllowedRedirectURIs() []string {
	var uris []string
	if err := json.Unmarshal([]byte(c.RedirectURIs), &uris); err != nil {
		log.Printf("Warning: client %s 的 redirect_uris 不是合法 JSON: %v", c.ClientID, err)
		return nil
	}
	return uris
}

// ResolveRedirectURI 决定这次把票据发到哪。
//
// requested 为空 = 用登记的第一个（§6.7）。传了就必须完全相等 ——
// 这里刻意不用 strings.HasPrefix：前缀匹配能被 `https://call.qwnet.top.evil.com` 绕过
func (c *SSOClient) ResolveRedirectURI(requested string) (string, bool) {
	allowed := c.AllowedRedirectURIs()
	if len(allowed) == 0 {
		return "", false
	}
	if requested == "" {
		return allowed[0], true
	}
	for _, uri := range allowed {
		if uri == requested {
			return uri, true
		}
	}
	return "", false
}

// DefaultSSOClients 启动时同步的应用注册表。
//
// **回调地址的形态取决于各应用的路由模式**：两个应用都是 Taro H5，
// config/index.ts 都没配 h5.router，走的是默认 hash 模式，所以地址里带
// `#/pages/...`。learn-daily 原来登记的是路径式 /auth/callback，与它的
// hash 路由对不上（精确匹配，跳回来会落到默认页丢掉 ticket），已一并改齐。
//
// ⚠️ Taro 的页面路径**带 `/index`**（其它页面也都长这样，见它的
// `utils/tabs.ts` 里的 DEFAULT_ROUTE），所以是 `#/pages/auth/callback/index` ——
// 少写那一段会被精确匹配直接拒掉（400），而且不会有任何"接近"的提示。
// 改这里之前先对一下前端 `utils/sso.ts` 的 CALLBACK_ROUTE
var DefaultSSOClients = []SSOClient{
	{
		ClientID: "call-front",
		Name:     "Call 游戏管理",
		RedirectURIs: `["http://localhost:3000/#/pages/auth/callback/index",` +
			`"https://call.qwnet.top/#/pages/auth/callback/index"]`,
		IsActive: true,
	},
	{
		ClientID: "learn-daily",
		Name:     "按天学",
		RedirectURIs: `["http://localhost:3010/#/pages/auth/callback/index",` +
			`"https://learn.qwnet.top/#/pages/auth/callback/index"]`,
		IsActive: true,
	},
}
