package services

import "errors"

// 领域错误。控制器用 errors.Is 判断，映射成对应的 HTTP 状态码和给前端的 error 标识。
//
// 这里刻意不把 HTTP 概念带进 service 层：service 只回答"业务上是什么错"，
// "该返回 401 还是 409"是控制器的事
var (
	// ErrInvalidCredentials 用户名或密码错误。
	//
	// **刻意不区分"用户名不存在"和"密码错误"**：分开说等于给攻击者一个
	// 用户名枚举接口 —— 他可以靠返回文案的差异筛出哪些用户名真实存在
	ErrInvalidCredentials = errors.New("用户名或密码错误")

	ErrAccountDisabled = errors.New("账号已被禁用")

	ErrUsernameTaken = errors.New("用户名已存在")

	// ErrInvalidUsername 用户名不符合要求
	ErrInvalidUsername = errors.New("用户名不符合要求")

	// ErrWeakPassword 密码不符合要求。
	//
	// 具体是哪一条不符合，由 service 用 %w 包一层带出去 —— 这样控制器既能用
	// errors.Is 判断类型，又能把"至少 8 位"这种具体原因显示给用户
	ErrWeakPassword = errors.New("密码不符合要求")

	// ErrTokenInvalid refresh token 不存在、已过期或已被吊销。
	// 正常过期走这里，前端收到就该重新登录
	ErrTokenInvalid = errors.New("登录态已失效，请重新登录")

	// ErrTokenReuse 检测到 refresh token 重放。
	//
	// 这意味着同一个 token 被用了两次 —— 客户端并发提交，或者 token 被偷了。
	// 分不清是哪种，所以一律按泄露处理：吊销该用户全部登录态。
	// 单独给它一个错误，是为了让前端能提示"检测到异常登录，请重新登录"，
	// 而不是笼统地说"登录态失效"
	ErrTokenReuse = errors.New("检测到令牌重复使用，已注销全部登录态以保护账号")

	// ErrInvalidSSORequest /sso 的参数校验不通过：client_id 不存在 / 已停用，
	// 或 redirect_uri 不在白名单里。
	//
	// **刻意只有这一个笼统的错误**：区分"client 不存在"和"redirect_uri 不合法"，
	// 等于给攻击者一个探测哪些 client_id 真实存在的接口（§6.7）。
	// 调用方拿到它只能回一个不带任何跳转的 400
	ErrInvalidSSORequest = errors.New("请求参数错误")

	// ErrSSOSessionInvalid SSO 会话不存在 / 已过期 / 已吊销。
	//
	// 「从没登录过」走的也是它 —— 对 /sso 来说那不是异常，只是该去登录页了
	ErrSSOSessionInvalid = errors.New("SSO 会话已失效")

	// ErrInvalidTicket 票据无效 / 已兑换 / 已过期 / client_id 对不上（§6.8）
	ErrInvalidTicket = errors.New("票据无效或已过期")
)
