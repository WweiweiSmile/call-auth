package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"call-auth/config"
	"call-auth/routes"
	"call-auth/services"
	"call-auth/utils"
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

// corsMiddleware 手写而不是引 gin-contrib/cors：规则很简单，
// 而且有一个点必须自己控制 —— AllowCredentials 为 true 时**不能**回 "*"，
// 浏览器会直接拒绝这个响应。所以这里只在 Origin 命中白名单时回显它
func corsMiddleware() gin.HandlerFunc {
	allowed := make(map[string]bool, len(config.AppConfig.CORSOrigins))
	for _, origin := range config.AppConfig.CORSOrigins {
		allowed[origin] = true
	}

	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")
		if origin != "" && allowed[origin] {
			ctx.Header("Access-Control-Allow-Origin", origin)
			ctx.Header("Access-Control-Allow-Credentials", "true")
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
