package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"call-auth/dto"
	"call-auth/services"
)

// context 里存的键名。与 call-back 保持一致，方便两边共用同一套前端约定
const (
	CtxUserID   = "user_id"
	CtxUsername = "username"
	CtxRole     = "role"
)

// AuthMiddleware 校验 Bearer access token。
//
// 注意它**不联网**：验签是拿本地公钥做的纯计算，认证中心不在请求路径上。
// 详见《认证中心设计文档》§3.4
func AuthMiddleware(tokens *services.TokenService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 放行预检请求，否则浏览器的 OPTIONS 会先被 401 挡掉
		if ctx.Request.Method == http.MethodOptions {
			ctx.Next()
			return
		}

		header := ctx.GetHeader("Authorization")
		if header == "" {
			abort(ctx, "未登录", "missing_token")
			return
		}

		parts := strings.SplitN(header, " ", 2)
		// 用 EqualFold 而不是 ==："bearer" 也是合法的，
		// RFC 7235 说 scheme 大小写不敏感
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			abort(ctx, "认证格式错误", "bad_authorization_header")
			return
		}

		claims, err := tokens.Verify(parts[1])
		if err != nil {
			abort(ctx, "登录态已失效，请重新登录", "invalid_token")
			return
		}

		userID, err := claims.UserID()
		if err != nil {
			abort(ctx, "登录态已失效，请重新登录", "invalid_token")
			return
		}

		ctx.Set(CtxUserID, userID)
		ctx.Set(CtxUsername, claims.Username)
		ctx.Set(CtxRole, claims.Role)
		ctx.Next()
	}
}

func abort(ctx *gin.Context, message, reason string) {
	ctx.AbortWithStatusJSON(http.StatusUnauthorized,
		dto.ErrorResponseWithReason(http.StatusUnauthorized, message, reason))
}

// GetUserID 从 context 取用户 id。中间件保证存在，取不到返回 0
func GetUserID(ctx *gin.Context) uint {
	if value, ok := ctx.Get(CtxUserID); ok {
		if id, ok := value.(uint); ok {
			return id
		}
	}
	return 0
}

// GetRole 从 context 取角色。它来自 token 的 claims，不查库 ——
// 所以改了角色要等 token 过期（最长 15 分钟）才生效
func GetRole(ctx *gin.Context) string {
	if value, ok := ctx.Get(CtxRole); ok {
		if role, ok := value.(string); ok {
			return role
		}
	}
	return ""
}

// IsAdmin 当前请求是不是管理员发起的
func IsAdmin(ctx *gin.Context) bool {
	return GetRole(ctx) == "admin"
}
