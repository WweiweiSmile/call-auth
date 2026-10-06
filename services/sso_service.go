package services

import (
	"log"
	"net/url"
	"strings"
	"time"

	"call-auth/config"
	"call-auth/models"
	"call-auth/utils"
)

// SSOService 跨应用票据交换（§4.5、§6.7、§6.8）。
//
// 它回答三个问题：这次跳转允许发到哪（ResolveClient）、来的人是谁
// （SessionUser）、票据怎么签发与核销（IssueTicket / ConsumeTicket）
type SSOService struct {
	tokens *TokenService
}

func NewSSOService(tokens *TokenService) *SSOService {
	return &SSOService{tokens: tokens}
}

// ResolveClient 校验 client_id 与 redirect_uri，返回最终跳回的目标地址。
//
// **失败一律返回同一个错误、不带任何细节**：区分「client 不存在」和
// 「redirect_uri 不在白名单」，等于给攻击者一个探测哪些 client_id 存在的接口（§6.7）。
// 调用方拿到 ErrInvalidSSORequest 只能回一个不带跳转的 400
func (s *SSOService) ResolveClient(clientID, requestedRedirectURI string) (string, error) {
	if clientID == "" {
		return "", ErrInvalidSSORequest
	}

	var client models.SSOClient
	if err := config.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return "", ErrInvalidSSORequest
	}
	if !client.IsActive {
		return "", ErrInvalidSSORequest
	}

	redirectURI, ok := client.ResolveRedirectURI(requestedRedirectURI)
	if !ok {
		log.Printf("Warning: client=%s 请求了不在白名单里的 redirect_uri", clientID)
		return "", ErrInvalidSSORequest
	}
	return redirectURI, nil
}

// SessionUser 读 SSO 会话（cookie 里那串明文），返回它属于谁。
//
// **会话不轮换**，这是刻意的：它是浏览器在认证中心域的长期登录态（30 天），
// 每次 /sso 都换一个新的会把「同一个 token 用两次」变成常态 —— 那正好撞上
// refresh token 的重放检测，把用户全部登录态吊销。**一次性的是票据，不是会话**
func (s *SSOService) SessionUser(plain string) (*models.User, error) {
	if plain == "" {
		return nil, ErrSSOSessionInvalid
	}

	var row models.RefreshToken
	if err := config.DB.
		Where("token_hash = ? AND scope = ?", utils.HashToken(plain), models.ScopeSSO).
		First(&row).Error; err != nil {
		return nil, ErrSSOSessionInvalid
	}
	if !row.IsUsable(time.Now()) {
		return nil, ErrSSOSessionInvalid
	}

	var user models.User
	if err := config.DB.First(&user, row.UserID).Error; err != nil {
		return nil, ErrSSOSessionInvalid
	}
	if !user.IsActive() {
		// 账号被禁用时顺手清掉这个会话，否则它会一直活到 30 天后。
		// 注意：不调 RevokeAll —— 那只在检测到泄露时用
		if err := s.tokens.Logout(user.ID, plain); err != nil {
			log.Printf("Warning: 清理被禁用账号的 SSO 会话失败: %v", err)
		}
		return nil, ErrSSOSessionInvalid
	}
	return &user, nil
}

// IssueTicket 签一张一次性票据（默认 60 秒）
func (s *SSOService) IssueTicket(userID uint, clientID, redirectURI string) (string, error) {
	plain, hash := utils.NewOpaqueToken()
	ticket := models.SSOTicket{
		TicketHash:  hash,
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(time.Duration(config.AppConfig.SSOTicketTTLSeconds) * time.Second),
	}
	if err := config.DB.Create(&ticket).Error; err != nil {
		return "", err
	}
	return plain, nil
}

// ConsumeTicket 核销票据并返回它属于谁。
//
// 用**条件更新**做原子的「占用」，和 refresh token 的轮换是同一套理由：
// 先读后判断再写会让同一张票被兑换两次
func (s *SSOService) ConsumeTicket(plain, clientID string) (*models.User, error) {
	if plain == "" || clientID == "" {
		return nil, ErrInvalidTicket
	}

	var ticket models.SSOTicket
	if err := config.DB.Where("ticket_hash = ?", utils.HashToken(plain)).First(&ticket).Error; err != nil {
		return nil, ErrInvalidTicket
	}

	// client_id 必须与签发时一致，否则 A 应用能拿 B 应用的票换 token（§6.8）
	if ticket.ClientID != clientID {
		log.Printf("Warning: 票据 client_id 不符：签发=%s 兑换=%s", ticket.ClientID, clientID)
		return nil, ErrInvalidTicket
	}

	now := time.Now()
	res := config.DB.Model(&models.SSOTicket{}).
		Where("id = ? AND used_at IS NULL AND expires_at > ?", ticket.ID, now).
		Update("used_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		// 已兑换或已过期。正常客户端不会重复提交同一张票（它是一次性的，
		// 兑换成功就该把 URL 上的 ticket 清掉），所以重复出现值得记一笔
		log.Printf("Warning: 票据重复兑换或已过期 client=%s", clientID)
		return nil, ErrInvalidTicket
	}

	var user models.User
	if err := config.DB.First(&user, ticket.UserID).Error; err != nil {
		return nil, ErrInvalidTicket
	}
	// 票据签发后被禁用的账号：兑换阶段再查一次。60 秒的窗口虽短，
	// 但一个已被禁用的账号能拿到 token，意味着禁用没有即时生效
	if !user.IsActive() {
		return nil, ErrAccountDisabled
	}
	return &user, nil
}

// CallbackURL 拼出带票据的回调地址。
//
// ⚠️ 这里是**纯字符串追加**，刻意不走 url.Parse：hash 模式的回调地址长这样
// `https://call.qwnet.top/#/pages/auth/callback` —— 参数必须拼在 `#` 之后，
// 成为 fragment 的一部分（浏览器不会把它发给服务端，顺带不进访问日志）。
// 用 url.Parse 再改 RawQuery 会把 `#/pages/...` 当成 fragment 直接丢掉，
// 跳转就废了
func CallbackURL(redirectURI, ticket, state string) string {
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	callback := redirectURI + sep + "ticket=" + url.QueryEscape(ticket)
	if state != "" {
		// state 原样带回，由应用侧比对（§8.4）
		callback += "&state=" + url.QueryEscape(state)
	}
	return callback
}

// LoginURL 拼出登录页地址。next 带的是**本次 /sso 的原始请求地址**
// （一定是以 `/sso?` 开头的相对路径，见 ValidNext）
func LoginURL(next string) string {
	return "/login?next=" + url.QueryEscape(next)
}

// ResolveLogoutTarget 决定全局退出后把用户送回哪，返回应用的 origin。
//
// next 只接受**某个 client 注册过的回调地址的 origin**（scheme://host[:port]），
// 白名单直接来自 sso_clients 表 —— 所以它不是任意跳转目标。
//
// 为什么返回 origin 而不是完整地址：注册的是回调页 `/auth/callback`，
// 跳过去那页会去找一个不存在的 ticket，直接是个报错页。登出后要回的是**应用首页**，
// 由它自己的路由守卫看到"没登录"再决定怎么办
func (s *SSOService) ResolveLogoutTarget(next string) (string, error) {
	if next == "" {
		return "", ErrInvalidSSORequest
	}

	parsed, err := url.Parse(next)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", ErrInvalidSSORequest
	}
	// 只接受纯 origin：带路径的一律拒，否则 next 又变成了任意跳转
	// （hash 模式的 fragment 不算路径，所以注册的那个回调地址形态也能通过，
	//   但它最终也只会被归约成 origin）
	if parsed.Path != "" && parsed.Path != "/" {
		return "", ErrInvalidSSORequest
	}

	var clients []models.SSOClient
	if err := config.DB.Find(&clients).Error; err != nil {
		return "", ErrInvalidSSORequest
	}
	for i := range clients {
		for _, uri := range clients[i].AllowedRedirectURIs() {
			registered, err := url.Parse(uri)
			if err != nil {
				continue
			}
			if registered.Scheme == parsed.Scheme && registered.Host == parsed.Host {
				return parsed.Scheme + "://" + parsed.Host, nil
			}
		}
	}
	return "", ErrInvalidSSORequest
}

// ValidNext 校验登录页带回来的 next。
//
// 这是认证中心自己域下的开放重定向防线，和 §6.7 的 redirect_uri 白名单是
// **两道独立的门**：next 防「拿本域当跳板」，白名单防「把票据送去恶意站点」。
//
// 只接受 `/sso?` 开头的相对路径就够了 —— 这个前缀天然排除了 `//evil.com`
// （协议相对 URL，浏览器会当成 https://evil.com）和 `https://evil.com`
func ValidNext(next string) bool {
	return strings.HasPrefix(next, "/sso?")
}
