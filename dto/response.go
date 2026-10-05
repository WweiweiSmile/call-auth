package dto

// Response 通用响应信封。
//
// 与 call-back 的形状保持一致（code/message/data），前端的请求层可以原样复用。
// 额外多一个 Error 字段：它是**给程序看的**错误标识（如 token_reuse_detected），
// Message 是给人看的。前端靠 Error 决定要不要弹"请重新登录"，而不是去匹配中文
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func SuccessResponse(data interface{}) Response {
	return Response{Code: 0, Message: "success", Data: data}
}

func ErrorResponse(message string) Response {
	return Response{Code: 1, Message: message}
}

// ErrorResponseWithCode 带业务错误码，code 通常与 HTTP 状态码一致
func ErrorResponseWithCode(code int, message string) Response {
	return Response{Code: code, Message: message}
}

// ErrorResponseWithReason 同时带错误码和程序可读的 reason
func ErrorResponseWithReason(code int, message, reason string) Response {
	return Response{Code: code, Message: message, Error: reason}
}
