package dto

// MaxPasswordBytes bcrypt 只取密码的前 72 个字节，更长的部分**被静默丢弃**。
// 也就是说超长密码的后半段根本不参与校验 —— 两个前 72 字节相同的密码会互相通过。
// 与其让用户以为设了个长密码更安全，不如直接拒掉
const MaxPasswordBytes = 72

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=100"`
	// max=72 是**字节**限制（见 MaxPasswordBytes）。中文密码一个字三字节，
	// 24 个汉字就到顶了，控制器里还会按字节再校一次
	Password string `json:"password" binding:"required,min=8,max=72"`
	Nickname string `json:"nickname"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	// ClientID 哪个应用发起的登录。现在只用于审计和「管理已登录设备」，
	// 不参与鉴权
	ClientID string `json:"client_id"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest RefreshToken 可选。
// 不传 = 登出该用户的**全部**应用登录态（"登出所有设备"）
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type UserInfo struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	// Role user/admin。前端据此渲染管理员入口；
	// 真正的权限判定在后端，不信任前端拿这个值做的任何决定
	Role string `json:"role"`
}

// TokenResponse 登录/注册/刷新统一返回这个结构
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	// RefreshToken **只在签发的那一刻返回一次**，服务端只存 sha256。
	// 前端必须持久化它，丢了就只能重新登录
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int      `json:"expires_in"` // access token 剩余秒数
	TokenType    string   `json:"token_type"` // 恒为 Bearer
	User         UserInfo `json:"user"`
}
