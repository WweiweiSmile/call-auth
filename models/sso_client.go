package models

import (
	"encoding/json"
	"log"
	"net/url"
	"time"
)

// SSOClient 应用注册表。
//
// **这张表是防开放重定向的关键**：/sso 只把票据发到表里登记过的 redirect_uri。
// 放行规则有两条，按顺序试（见 ResolveRedirectURI）：
//  1. 逐字相等 —— 登记什么就只发什么，最严
//  2. 同源放行 —— scheme+host 与某个登记项精确相等时，路径自由
//
// 第 2 条是为了让调用方能把「用户当时所在的那一页」作为落点（登录完直接回那一页，
// 而不是回一个固定回调页）。它**不是**把口子开大：票据仍然只能落到本应用自己的域，
// 攻击者拿不到 —— 防的仍是「把票据送去恶意站点」（§4.5、§6.7）。
//
// ⚠️ 同源比较必须走 url.Parse 后的 Scheme/Host 精确相等，**绝不能**退回
// strings.HasPrefix：前缀匹配会被 `https://call.qwnet.top.evil.com` 绕过
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
// requested 为空 = 用登记的第一个（§6.7）。传了就走两步：
// 逐字相等优先，否则同源放行（见下方注释）。
func (c *SSOClient) ResolveRedirectURI(requested string) (string, bool) {
	allowed := c.AllowedRedirectURIs()
	if len(allowed) == 0 {
		return "", false
	}
	if requested == "" {
		return allowed[0], true
	}

	// 1. 逐字相等。登记什么就只发什么 —— 老调用方（不带 redirect_uri 习惯的）
	//    和"只想放行一个固定回调页"的 client 走的都是这条
	for _, uri := range allowed {
		if uri == requested {
			return uri, true
		}
	}

	// 2. 同源放行：scheme 和 host 都要与某个登记项精确相等，路径和查询串自由。
	//
	// host 精确相等这一条就挡住了两个经典绕过：
	//   https://call.qwnet.top.evil.com/x  → host 是 call.qwnet.top.evil.com，不等
	//   https://call.qwnet.top@evil.com/x  → url.Parse 把 @ 前当 userinfo，host 是 evil.com
	// 所以这里刻意不用 strings.HasPrefix，那两种都能骗过前缀匹配
	req, err := url.Parse(requested)
	if err != nil || req.Scheme == "" || req.Host == "" {
		return "", false
	}
	for _, uri := range allowed {
		registered, err := url.Parse(uri)
		if err != nil {
			continue
		}
		// Host 含端口，所以「同域不同端口」也会被拒 —— 与 ResolveLogoutTarget
		// 里的比较方式一致，两处是同一个判据
		if registered.Scheme == req.Scheme && registered.Host == req.Host {
			return requested, true
		}
	}
	return "", false
}

// DefaultSSOClients 启动时同步的应用注册表。
//
// **地址的形态取决于各应用的路由模式**：两个应用现在都是 Taro H5 的
// history 模式（`h5.router.mode = 'browser'`），所以地址里**不带 `#`**。
// 以前是默认的 hash 模式、地址形如 `#/pages/...`；切 history 后老形态作废。
//
// 登记的路径取的是各应用的**默认落点页**（与 app.config.ts 的 entryPagePath 一致），
// 因为 ResolveRedirectURI 在调用方没传 redirect_uri 时回退到 allowed[0] ——
// 那一条得是个人能看的页面，不能是根路径 `/`（history 模式下根路径不会自动
// 路由到 entryPagePath）也不能是已经删掉的回调页。
//
// 平时调用方都会显式传 redirect_uri（前端把用户当时所在的那一页传过来），
// 路径部分由同源放行覆盖，不依赖这里登记的具体路径是否吻合。
//
// ⚠️ Taro 的页面路径**带 `/index`**（其它页面也都长这样，见各应用的
// `utils/tabs.ts` 里的 DEFAULT_ROUTE）。改这里之前先对一下前端的 DEFAULT_ROUTE
//
// ⚠️ 这里的内容每次启动都会覆盖数据库（见 config.seedSSOClients）——
// 直接 UPDATE 表会在下次重启被冲掉
var DefaultSSOClients = []SSOClient{
	{
		ClientID: "call-front",
		Name:     "Call 游戏管理",
		RedirectURIs: `["http://localhost:3000",` +
			`"http://call.qwnet.top"]`,
		IsActive: true,
	},
	{
		ClientID: "learn-daily",
		Name:     "按天学",
		RedirectURIs: `["http://localhost:3010",` +
			`"http://learn.qwnet.top"]`,
		IsActive: true,
	},
}
