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
	authController := controllers.NewAuthController(
		services.NewAuthService(tokens),
		tokens,
	)

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
