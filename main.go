package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"call-auth/config"
	"call-auth/routes"
	"call-auth/services"
	"call-auth/utils"
	"call-auth/web"
)

func main() {
	// 1. 配置。缺 AUTH_PRIVATE_KEY_PATH 会在这里直接退出 —— 密钥没有默认值，
	//    漏配必须立刻知道（详见 config.requireEnv 的说明）
	if err := config.LoadConfig(); err != nil {
		log.Fatal("配置加载失败: ", err)
	}

	// 2. 密钥。放在数据库之前：连不上库是运维问题，密钥出问题则是整个体系的地基，
	//    先把它确定下来
	keys, err := utils.LoadOrCreateKeyPair(config.AppConfig.AuthPrivateKeyPath)
	if err != nil {
		log.Fatal("加载签名密钥失败: ", err)
	}

	// 3. 数据库。用的是 call-back 的库，users 表归它管
	if err := config.InitDB(); err != nil {
		log.Fatal("数据库连接失败: ", err)
	}
	if err := config.Migrate(); err != nil {
		log.Fatal("数据表检查失败: ", err)
	}

	tokens := services.NewTokenService(keys)

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(corsMiddleware())

	// 登录页。必须住在认证中心自己域名下 —— 跨域时前端 JS 无法为别的域写
	// cookie，能种下 auth 域会话 cookie 的只有 auth 域自己（§4.5）
	tmpl := template.Must(template.ParseFS(web.Templates, "templates/*.html"))
	r.SetHTMLTemplate(tmpl)

	routes.SetupRoutes(r, tokens)

	if len(config.AppConfig.CORSOrigins) == 0 {
		log.Println("Warning: CORS_ORIGINS 为空，浏览器端的请求会全部被同源策略挡掉。" +
			"本地开发请至少加上 http://localhost:3000")
	}
	log.Printf("call-auth 就绪：:%s  issuer=%s  kid=%s  aud=%v",
		config.AppConfig.ServerPort, config.AppConfig.AuthIssuer, keys.Kid, config.AppConfig.AuthAudiences)

	if err := r.Run(":" + config.AppConfig.ServerPort); err != nil {
		log.Fatal("服务启动失败: ", err)
	}
}

// corsMiddleware 手写而不是引 gin-contrib/cors：规则很简单。
//
// **刻意不回 Access-Control-Allow-Credentials**：登录页搬到认证中心之后，
// 认证域的 cookie 只在顶层导航（GET /sso）和同源表单（POST /login）里用，
// 这两处都不经过 CORS；唯一跨域的 POST /auth/ticket 用票据自证、不读 cookie。
// 所以没有任何一处需要带凭据 —— 不开这个头本身就是一层收紧（§9.3）
func corsMiddleware() gin.HandlerFunc {
	allowed := make(map[string]bool, len(config.AppConfig.CORSOrigins))
	for _, origin := range config.AppConfig.CORSOrigins {
		allowed[origin] = true
	}

	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")
		if origin != "" && allowed[origin] {
			ctx.Header("Access-Control-Allow-Origin", origin)
			// Vary 必须带上 Origin：否则 CDN/代理会把 A 站点的响应
			// 缓存下来发给 B 站点，把 CORS 头带错
			ctx.Header("Vary", "Origin")
		}

		if ctx.Request.Method == http.MethodOptions {
			ctx.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			ctx.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
			ctx.Header("Access-Control-Max-Age", "86400")
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}

		ctx.Next()
	}
}
