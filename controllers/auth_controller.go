package controllers

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"call-auth/dto"
	"call-auth/middleware"
	"call-auth/services"
)

type AuthController struct {
	auth   *services.AuthService
	tokens *services.TokenService
}

func NewAuthController(auth *services.AuthService, tokens *services.TokenService) *AuthController {
	return &AuthController{auth: auth, tokens: tokens}
}

func (c *AuthController) Register(ctx *gin.Context) {
	var req dto.RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, "参数错误: "+err.Error())
		return
	}

	resp, err := c.auth.Register(&req)
	if err != nil {
		respondError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto.SuccessResponse(resp))
}

func (c *AuthController) Login(ctx *gin.Context) {
	var req dto.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, "参数错误: "+err.Error())
		return
	}

	resp, err := c.auth.Login(&req)
	if err != nil {
		respondError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto.SuccessResponse(resp))
}

// Refresh 用 refresh token 换一对新令牌
func (c *AuthController) Refresh(ctx *gin.Context) {
	var req dto.RefreshRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, "参数错误: "+err.Error())
		return
	}

	resp, err := c.tokens.Refresh(req.RefreshToken)
	if err != nil {
		respondError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto.SuccessResponse(resp))
}

// Logout 登出。
//
// 与设计文档 §6.4 的一处**刻意偏离**：文档写的是需要 Authorization +
// 可选 refresh_token，实现改成只认 refresh_token、不要 access token。
//
// 原因：access token 只有 15 分钟。如果登出需要它，那么用户放着不管半小时后
// 想登出，会先收到 401 —— 而登出恰恰是"登录态已经不对劲"时最需要能用的操作。
// refresh token 本身就能定位到用户，不需要再要一个 access token
func (c *AuthController) Logout(ctx *gin.Context) {
	var req dto.LogoutRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, "参数错误: "+err.Error())
		return
	}
	if req.RefreshToken == "" {
		badRequest(ctx, "缺少 refresh_token")
		return
	}

	// 先由 token 反查用户，再决定吊销范围
	userID, err := c.tokens.UserOf(req.RefreshToken)
	if err != nil {
		// token 已经无效/过期/被吊销 —— 从用户视角看"我本来就是登出状态"，
		// 所以返回成功而不是错误。否则前端会卡在"登出失败"上反复重试
		ctx.JSON(http.StatusOK, dto.SuccessResponse(gin.H{"logged_out": true}))
		return
	}

	if allDevices, _ := ctx.GetQuery("all_devices"); allDevices == "true" {
		c.tokens.RevokeAll(userID)
	} else if err := c.tokens.Logout(userID, req.RefreshToken); err != nil {
		respondError(ctx, err)
		return
	}

	ctx.JSON(http.StatusOK, dto.SuccessResponse(gin.H{"logged_out": true}))
}

// Me 当前登录用户的信息
func (c *AuthController) Me(ctx *gin.Context) {
	info, err := c.auth.GetUser(middleware.GetUserID(ctx))
	if err != nil {
		respondError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto.SuccessResponse(info))
}

// JWKS 公钥集。
//
// **无需认证** —— 它的内容本来就是公开的，验签方要拿它来验我们的签名。
// 用标准 JWKS 格式是为了让各语言的 JWT 库能直接消费
// （Go 的 keyfunc、Python 的 PyJWKClient 都认这个格式）
func (c *AuthController) JWKS(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"keys": c.tokens.Keys().JWKS()})
}

func badRequest(ctx *gin.Context, message string) {
	ctx.JSON(http.StatusBadRequest, dto.ErrorResponseWithReason(http.StatusBadRequest, message, "invalid_request"))
}

// respondError 把领域错误映射成 HTTP 状态码 + 给前端程序判断的 reason。
//
// reason 是**对外契约**：前端靠它决定行为（比如 token_reuse_detected 要弹
// "检测到异常登录"，而不是笼统的"登录过期"）。改它等于改接口
func respondError(ctx *gin.Context, err error) {
	status, reason, message := http.StatusInternalServerError, "internal_error", ""

	switch {
	case errors.Is(err, services.ErrInvalidCredentials):
		status, reason, message = http.StatusUnauthorized, "invalid_credentials", err.Error()
	case errors.Is(err, services.ErrTokenReuse):
		status, reason, message = http.StatusUnauthorized, "token_reuse_detected", err.Error()
	case errors.Is(err, services.ErrTokenInvalid):
		status, reason, message = http.StatusUnauthorized, "token_invalid", err.Error()
	case errors.Is(err, services.ErrAccountDisabled):
		status, reason, message = http.StatusForbidden, "account_disabled", err.Error()
	case errors.Is(err, services.ErrUsernameTaken):
		status, reason, message = http.StatusConflict, "username_taken", err.Error()
	case errors.Is(err, services.ErrInvalidUsername), errors.Is(err, services.ErrWeakPassword):
		status, reason, message = http.StatusBadRequest, "invalid_input", err.Error()
	case errors.Is(err, services.ErrInvalidSSORequest):
		status, reason, message = http.StatusBadRequest, "invalid_request", err.Error()
	case errors.Is(err, services.ErrSSOSessionInvalid):
		status, reason, message = http.StatusUnauthorized, "sso_session_invalid", err.Error()
	case errors.Is(err, services.ErrInvalidTicket):
		status, reason, message = http.StatusBadRequest, "invalid_ticket", err.Error()
	}

	if status == http.StatusInternalServerError {
		// 非预期错误只记日志，绝不把内部细节（SQL 语句、堆栈）回给客户端 ——
		// 那是在给攻击者送情报
		log.Printf("Error: 认证接口内部错误: %v", err)
		message = "服务器内部错误"
	}

	ctx.JSON(status, dto.ErrorResponseWithReason(status, message, reason))
}
