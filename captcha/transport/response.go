package transport

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/json"
)

// apiResponse is the HTTP envelope shared by every captcha endpoint. | apiResponse 是验证码端点共用的 HTTP 信封。
type apiResponse struct {
	// Challenge is present after create or send. | Challenge 在创建或发送后存在。
	Challenge *Challenge `json:"challenge,omitempty"`
	// Result is present after verification. | Result 在验证后存在。
	Result *VerifyResult `json:"result,omitempty"`
	// Claims is present after token consumption. | Claims 在令牌消费后存在。
	Claims *TokenClaims `json:"claims,omitempty"`
	// Error is present on failure. | Error 在失败时存在。
	Error *apiError `json:"error,omitempty"`
	// OK reports success. | OK 报告是否成功。
	OK bool `json:"ok"`
}

// apiError is the public error body. | apiError 是公开错误正文。
type apiError struct {
	// Code is a stable machine-readable error code. | Code 是稳定的机器可读错误码。
	Code string `json:"code"`
	// Message is a human-readable message localized by request language. | Message 是按请求语言本地化的人类可读消息。
	Message string `json:"message"`
	// RetryAfter is the suggested wait in seconds. | RetryAfter 是建议等待秒数。
	RetryAfter int64 `json:"retry_after,omitempty"`
}

// writeJSON writes one JSON response with no-store caching. | writeJSON 写出一个禁止缓存的 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		payload = []byte(`{"ok":false,"error":{"code":"internal_error","message":"captcha request failed | 验证码请求失败"}}`)
	}
	header := w.Header()
	header["Content-Type"] = []string{"application/json; charset=utf-8"}
	header["Cache-Control"] = []string{"no-store"}
	header["X-Content-Type-Options"] = []string{"nosniff"}
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// writeChallenge writes a successful create or send response. | writeChallenge 写出成功的创建或发送响应。
func writeChallenge(w http.ResponseWriter, challenge *Challenge) {
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Challenge: challenge})
}

// writeResult writes a successful verification response. | writeResult 写出成功的验证响应。
func writeResult(w http.ResponseWriter, result *VerifyResult) {
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Result: result})
}

// writeClaims writes a successful token-consumption response. | writeClaims 写出成功的令牌消费响应。
func writeClaims(w http.ResponseWriter, claims *TokenClaims) {
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Claims: claims})
}

// writeAPIError maps a sentinel error to one HTTP response. | writeAPIError 把哨兵错误映射为一个 HTTP 响应。
func writeAPIError(w http.ResponseWriter, err error) {
	writeAPIErrorWith(w, err, "")
}

// writeAPIErrorWith writes an API error with an optional localized message. | writeAPIErrorWith 写出可带本地化文案的 API 错误。
func writeAPIErrorWith(w http.ResponseWriter, err error, message string) {
	status, code, fallback := mapError(err)
	if message == "" {
		message = fallback
	}
	body := apiResponse{OK: false, Error: &apiError{Code: code, Message: message}}
	var limit *LimitError
	var cooldown *CooldownError
	switch {
	case errors.As(err, &limit):
		wait := secondsCeil(limit.RetryAfter)
		if wait < 1 {
			wait = 1
		}
		body.Error.RetryAfter = wait
		w.Header()["Retry-After"] = []string{strconv.FormatInt(wait, 10)}
	case errors.As(err, &cooldown):
		wait := secondsCeil(cooldown.RetryAfter)
		if wait < 1 {
			wait = 1
		}
		body.Error.RetryAfter = wait
		w.Header()["Retry-After"] = []string{strconv.FormatInt(wait, 10)}
	case errors.Is(err, ErrTooManyAttempts):
		w.Header()["Retry-After"] = []string{"1"}
		body.Error.RetryAfter = 1
	}
	writeJSON(w, status, body)
}

// secondsCeil converts a duration to whole seconds, rounding up. | secondsCeil 把时长向上取整为秒。
func secondsCeil(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// mapError returns the status, public code and public message for err. | mapError 返回 err 的状态、公开码与公开消息。
func mapError(err error) (int, string, string) {
	code := core.ErrorCode(err)
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest, code, "invalid captcha request | 非法验证码请求"
	case errors.Is(err, ErrUnsupportedMediaType):
		return http.StatusUnsupportedMediaType, code, "captcha requires application/json | 验证码请求需要 application/json"
	case errors.Is(err, ErrRequestTooLarge):
		return http.StatusRequestEntityTooLarge, code, "captcha request body is too large | 验证码请求正文过大"
	case errors.Is(err, ErrInvalidType), errors.Is(err, ErrInvalidAnswer), errors.Is(err, ErrInvalidTarget),
		errors.Is(err, ErrUnsupportedChannel), errors.Is(err, ErrPoWRequired), errors.Is(err, ErrPoWInvalid),
		errors.Is(err, ErrInvalidOptions):
		return http.StatusBadRequest, code, err.Error()
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrGeoBlocked), errors.Is(err, ErrGeoMismatch),
		errors.Is(err, ErrRiskRejected), errors.Is(err, ErrOriginNotAllowed), errors.Is(err, ErrCaptureDetected), errors.Is(err, ErrFallbackDisabled):
		return http.StatusForbidden, code, err.Error()
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, code, ErrNotFound.Error()
	case errors.Is(err, ErrExpired):
		return http.StatusGone, code, ErrExpired.Error()
	case errors.Is(err, ErrTokenUsed):
		return http.StatusConflict, code, ErrTokenUsed.Error()
	case errors.Is(err, ErrRateLimited), errors.Is(err, ErrCooldown), errors.Is(err, ErrTooManyAttempts):
		return http.StatusTooManyRequests, code, err.Error()
	case errors.Is(err, ErrNoSender):
		return http.StatusServiceUnavailable, code, ErrNoSender.Error()
	case errors.Is(err, ErrSendFailed):
		return http.StatusBadGateway, code, "captcha code delivery failed | 验证码下发失败"
	case errors.Is(err, ErrProvider), errors.Is(err, ErrStore):
		return http.StatusServiceUnavailable, code, "captcha service unavailable | 验证码服务暂不可用"
	case errors.Is(err, ErrClosed):
		return http.StatusServiceUnavailable, code, ErrClosed.Error()
	case errors.Is(err, ErrTokenInvalid):
		return http.StatusUnauthorized, code, ErrTokenInvalid.Error()
	case errors.Is(err, ErrTokenExpired):
		return http.StatusUnauthorized, code, ErrTokenExpired.Error()
	default:
		return http.StatusInternalServerError, code, "captcha request failed | 验证码请求失败"
	}
}

// validHeaderName reports whether name is a safe HTTP header token. | validHeaderName 报告 name 是否为安全的 HTTP 头 token。
func validHeaderName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// corsOrigin returns the allowed Origin response value. | corsOrigin 返回允许的 Origin 响应值。
func corsOrigin(origin string, allowed []string) (string, bool) {
	if origin == "" || len(allowed) == 0 {
		return "", false
	}
	for _, candidate := range allowed {
		if candidate == "*" {
			return "*", true
		}
		if candidate == origin {
			return origin, true
		}
	}
	return "", false
}

// setCORSHeaders applies the CORS response headers for an allowed origin. | setCORSHeaders 为允许的 Origin 设置 CORS 响应头。
//
// requestedHeaders is the browser's Access-Control-Request-Headers value; valid
// custom header names are reflected so cross-origin SDK headers can pass
// preflight. | requestedHeaders 是浏览器的 Access-Control-Request-Headers；
// 合法的自定义头会被回显，使跨域 SDK 自定义头通过预检。
func setCORSHeaders(w http.ResponseWriter, origin string, allowed []string, requestedHeaders ...string) bool {
	value, ok := corsOrigin(origin, allowed)
	if !ok {
		return false
	}
	header := w.Header()
	header["Access-Control-Allow-Origin"] = []string{value}
	header["Access-Control-Allow-Methods"] = []string{"GET, POST, OPTIONS"}
	allowHeaders := "Content-Type, X-Captcha-Token, Authorization, X-Lang"
	for _, value := range requestedHeaders {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if validHeaderName(name) && !strings.Contains(strings.ToLower(allowHeaders), strings.ToLower(name)) {
				allowHeaders += ", " + name
			}
		}
	}
	header["Access-Control-Allow-Headers"] = []string{allowHeaders}
	header["Access-Control-Max-Age"] = []string{strconv.FormatInt(int64((10 * time.Minute).Seconds()), 10)}
	if value != "*" {
		addVary(w, "Origin")
	}
	return true
}
