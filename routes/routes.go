package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"call-auth/controllers"
	"call-auth/middleware"
	"call-auth/services"
)

// SetupRoutes 注册全部路由
func SetupRoutes(r *gin.Engine, tokens *services.TokenService) {
	authService := services.NewAuthService(tokens)
	authController := controllers.NewAuthController(authService, tokens)
	ssoController := controllers.NewSSOController(
		services.NewSSOService(tokens),
		authService,
		tokens,
	)

	// 浏览器导航入口与登录页。
	//
	// 刻意**不放在 /api/v1 下**：那个前缀是给 XHR 和脚本用的 API 空间，
	// 而这几条是「点开一个链接」走的 —— 返回 302 或 HTML，不是 JSON。
	// 分开也让 CORS 白名单能一眼看出哪些是给浏览器直接打开的
	r.GET("/sso", ssoController.SSO)
	r.GET("/login", ssoController.LoginPage)
	r.POST("/login", ssoController.LoginSubmit)
	r.POST("/register", ssoController.RegisterSubmit)
	// 全局退出。同样必须在认证中心域下 —— 只有它能删掉自己的会话 cookie
	r.GET("/logout", ssoController.Logout)

	// JWKS 挂在根路径下：这是标准位置，各语言的 JWT 库默认就按这个约定去找。
	// 放到 /api/v1 下面会让它们多一项配置
	r.GET("/.well-known/jwks.json", authController.JWKS)

	// 健康检查。部署探活用，不需要认证
	r.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	api := r.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			// 无需登录
			auth.POST("/register", authController.Register)
			auth.POST("/login", authController.Login)
			// refresh 用 refresh token 自证身份，不需要 access token ——
			// 恰恰是 access 过期了才来调它
			auth.POST("/refresh", authController.Refresh)
			// 用一次性票据换令牌。票据自己就是凭据，不需要 access token ——
			// 恰恰是前端还没登录（只有 ticket）的时候才来调它
			auth.POST("/ticket", ssoController.Ticket)
			// logout 同理，见 controller 里的说明
			auth.POST("/logout", authController.Logout)

			// 需要登录
			authorized := auth.Group("")
			authorized.Use(middleware.AuthMiddleware(tokens))
			{
				authorized.GET("/me", authController.Me)
			}
		}
	}
}
