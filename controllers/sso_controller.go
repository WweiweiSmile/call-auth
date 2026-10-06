package controllers

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"call-auth/config"
	"call-auth/dto"
	"call-auth/models"
	"call-auth/services"
)

// CookieName SSO 会话 cookie 的名字。
// 它装的是 scope='sso' 那个 token 的**明文**，不是 access token（§7.2）
const CookieName = "sso_session"

// SSOController 浏览器侧的登录与票据交换。
//
// 与其他控制器不同，这些接口**返回 302 或 HTML，不是 JSON** —— 它们是浏览器
// 导航的入口（点开链接、提交表单），不是给 XHR 调的。唯一例外是 Ticket
type SSOController struct {
	sso    *services.SSOService
	auth   *services.AuthService
	tokens *services.TokenService
}

func NewSSOController(
	sso *services.SSOService,
	auth *services.AuthService,
	tokens *services.TokenService,
) *SSOController {
	return &SSOController{sso: sso, auth: auth, tokens: tokens}
}

// SSO GET /sso —— 浏览器导航入口。永远返回 302 或 400，不返回 JSON
func (c *SSOController) SSO(ctx *gin.Context) {
	clientID := ctx.Query("client_id")
	state := ctx.Query("state")

	redirectURI, err := c.sso.ResolveClient(clientID, ctx.Query("redirect_uri"))
	if err != nil {
		// 400，且**不回显任何跳转**。
		// 也不要"校验失败就跳首页" —— 那会让攻击者能探测哪些 client_id 存在（§6.7）
		ctx.String(http.StatusBadRequest, "请求参数错误")
		return
	}

	// 这个浏览器上登录过（认证中心域下有会话）→ 直接发票据，用户无感
	if plain, err := ctx.Cookie(CookieName); err == nil {
		if user, err := c.sso.SessionUser(plain); err == nil {
			ticket, err := c.sso.IssueTicket(user.ID, clientID, redirectURI)
			if err != nil {
				log.Printf("Error: 签发票据失败: %v", err)
				ctx.String(http.StatusInternalServerError, "服务器内部错误")
				return
			}
			ctx.Redirect(http.StatusFound, services.CallbackURL(redirectURI, ticket, state))
			return
		}
		// 会话无效 / 已过期 → 落到下面去登录页。这里刻意不删 cookie：
		// 它每次登录都会被覆盖，而删它要走一次 Set-Cookie，没必要
	}

	// 没有会话 → 去登录页。next 带的是**本次 /sso 的原始地址**，
	// 登录成功后回到这里继续发票据（§6.2.1）
	ctx.Redirect(http.StatusFound, services.LoginURL(ctx.Request.URL.RequestURI()))
}

// LoginPage GET /login —— 渲染登录页
func (c *SSOController) LoginPage(ctx *gin.Context) {
	next := ctx.Query("next")
	if !services.ValidNext(next) {
		// next 非法就**不渲染表单**：表单里会把它原样带回去，
		// 渲染出来等于把那个跳转目标摆在那儿等人去点
		ctx.String(http.StatusBadRequest, "请求参数错误")
		return
	}
	ctx.HTML(http.StatusOK, "login.html",
		loginView(next, ctx.Query("mode") == "register", "", ""))
}

// LoginSubmit POST /login —— 表单登录
func (c *SSOController) LoginSubmit(ctx *gin.Context) {
	c.submitForm(ctx, false)
}

// RegisterSubmit POST /register —— 表单注册。
//
// 单独有它，是因为登录页带注册切换：注册成功也必须是"已登录"，
// 否则用户注册完还要再登一次，"注册成功"和"已登录"会变成两套状态（§6.2.1）
func (c *SSOController) RegisterSubmit(ctx *gin.Context) {
	c.submitForm(ctx, true)
}

func (c *SSOController) submitForm(ctx *gin.Context, register bool) {
	next := ctx.PostForm("next")
	if !services.ValidNext(next) {
		ctx.String(http.StatusBadRequest, "请求参数错误")
		return
	}

	username := ctx.PostForm("username")
	password := ctx.PostForm("password")

	var user *models.User
	var err error
	if register {
		user, err = c.auth.RegisterUser(&dto.RegisterRequest{
			Username: username,
			Password: password,
			Nickname: ctx.PostForm("nickname"),
		})
	} else {
		user, err = c.auth.Authenticate(username, password)
	}

	if err != nil {
		// 失败**不 302**，把错误渲染回同一个表单 —— 跳走了用户就看不到错在哪。
		// 用 200 而不是 4xx：这是"页面渲染结果"，让浏览器正常显示它；
		// 真正的错误在页面里
		ctx.HTML(http.StatusOK, "login.html",
			loginView(next, register, username, describeFormError(err)))
		return
	}

	plain, err := c.tokens.IssueSSOSession(user)
	if err != nil {
		log.Printf("Error: 建 SSO 会话失败: %v", err)
		ctx.HTML(http.StatusInternalServerError, "login.html",
			loginView(next, register, username, "服务器内部错误，请稍后再试"))
		return
	}

	c.setSessionCookie(ctx, plain)

	// 回 next（也就是 /sso），由它发票据 —— 不是直接回应用（§6.2.1）
	ctx.Redirect(http.StatusFound, next)
}

// Logout GET /logout —— **全局退出**。
//
// 为什么必须有它：登录之后，各前端点「登出」会清掉自己的 storage，但认证中心
// 域下的 SSO 会话 cookie **前端删不掉**（HttpOnly，而且跨域时 JS 连读都读不到）。
// 于是路由守卫判定"没登录" → 跳 /sso → 立刻又被静默登回去 —— 登出按钮变成一个
// 闪一下就回来的死循环。能删那个 cookie 的只有认证中心自己（§6.2.1）
//
// 语义是**全局退出**：吊销该用户的全部登录态，包括其他应用的 app 类登录态。
// 这是刻意的 —— 用户按「登出」时期望的是"我哪儿都退了"，而不是"只退了这个应用，
// 点一下又进去了"。（如果哪天要「只退本应用」，那是另一个按钮、另一个接口）
//
// ⚠️ 已知并接受：这是个 GET，所以存在「登出 CSRF」—— 恶意页面可以让用户导航到这里
// 把他登出。影响仅限于"被登出"，不泄露数据、不涉及账号接管，和多数 IdP 的选择一致。
// 真要防，得让应用改用带一次性 token 的 POST，代价是前端要能发跨域表单
func (c *SSOController) Logout(ctx *gin.Context) {
	target, err := c.sso.ResolveLogoutTarget(ctx.Query("next"))
	if err != nil {
		ctx.String(http.StatusBadRequest, "请求参数错误")
		return
	}

	// 会话有效 → 连该用户其他应用的登录态一起吊销；无效 → 只清 cookie。
	// 不做错误提示：从用户视角看"我本来就是登出状态"，登出该是幂等的
	if plain, err := ctx.Cookie(CookieName); err == nil {
		if user, err := c.sso.SessionUser(plain); err == nil {
			c.tokens.RevokeAll(user.ID)
		}
	}

	c.clearSessionCookie(ctx)
	ctx.Redirect(http.StatusFound, target)
}

// Ticket POST /auth/ticket —— 应用前端拿票据换令牌（§6.8）
func (c *SSOController) Ticket(ctx *gin.Context) {
	var req dto.TicketRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, "参数错误: "+err.Error())
		return
	}

	user, err := c.sso.ConsumeTicket(req.Ticket, req.ClientID)
	if err != nil {
		respondError(ctx, err)
		return
	}

	// 换出来的是**应用登录态**（scope='app'），和 /auth/login 拿到的完全一样：
	// 响应形状一致，前端存 token 的那段代码不用区分来源
	resp, err := c.tokens.Issue(user, req.ClientID)
	if err != nil {
		respondError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto.SuccessResponse(resp))
}

// setSessionCookie 种下 SSO 会话。
//
// Domain 刻意不设：host-only，绑死认证中心这一个域，其他子域拿不到它。
// HttpOnly：JS 读不到，XSS 也偷不走 —— 它可是个 30 天有效的凭据。
// SameSite=Lax：顶层导航（GET /sso）会带上，够用；不能用 None —— 它强制要求
// Secure，而本机开发是 http。
// Secure：由 COOKIE_SECURE 控制，**不能硬编码**：硬编码 true 时本机
// http://localhost:8020 完全登不进去（浏览器直接不存这个 cookie），
// 现象是 /sso 死循环跳登录页
func (c *SSOController) setSessionCookie(ctx *gin.Context, value string) {
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   config.AppConfig.SSOSessionTTLSeconds,
		HttpOnly: true,
		Secure:   config.AppConfig.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie 删掉 SSO 会话 cookie。
//
// 属性必须与 setSessionCookie 里**完全一致**（Name / Path / Domain）：
// 浏览器是按「名字 + 域 + 路径」区分 cookie 的，对不上就是删了另一个，
// 真的那个还留着 —— 表现为登出后刷新一次又是登录态
func (c *SSOController) clearSessionCookie(ctx *gin.Context) {
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // 负数 = 立刻删除
		HttpOnly: true,
		Secure:   config.AppConfig.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// loginView 登录页的模板数据。集中在一处，免得两个渲染点漏字段
func loginView(next string, register bool, username, errMessage string) gin.H {
	return gin.H{
		"Next":     next,
		"Register": register,
		"Username": username,
		"Error":    errMessage,
	}
}

// describeFormError 把领域错误翻译成能直接显示给用户的一句话
func describeFormError(err error) string {
	switch {
	case errors.Is(err, services.ErrInvalidCredentials):
		return "用户名或密码错误"
	case errors.Is(err, services.ErrAccountDisabled):
		return "账号已被禁用"
	case errors.Is(err, services.ErrUsernameTaken):
		return "用户名已存在，换一个吧"
	case errors.Is(err, services.ErrWeakPassword), errors.Is(err, services.ErrInvalidUsername):
		// 这两个错误用 %w 包了具体原因（"至少 8 位"），原文比笼统的提示有用
		return err.Error()
	default:
		log.Printf("Error: 表单登录内部错误: %v", err)
		return "服务器内部错误，请稍后再试"
	}
}
