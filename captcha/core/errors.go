package core

import "errors"

// ErrorCode returns a stable public error code. | ErrorCode 返回稳定的公开错误码。
func ErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	case errors.Is(err, ErrGeoBlocked):
		return "geo_blocked"
	case errors.Is(err, ErrGeoMismatch):
		return "geo_mismatch"
	case errors.Is(err, ErrCaptureDetected):
		return "capture_detected"
	case errors.Is(err, ErrFallbackDisabled):
		return "fallback_disabled"
	case errors.Is(err, ErrUnsupportedMediaType):
		return "unsupported_media_type"
	case errors.Is(err, ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, ErrCooldown):
		return "cooldown"
	case errors.Is(err, ErrInvalidAnswer):
		return "invalid_answer"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrTooManyAttempts):
		return "too_many_attempts"
	case errors.Is(err, ErrRiskRejected):
		return "risk_rejected"
	case errors.Is(err, ErrPoWRequired):
		return "pow_required"
	case errors.Is(err, ErrPoWInvalid):
		return "pow_invalid"
	case errors.Is(err, ErrSendFailed):
		return "send_failed"
	case errors.Is(err, ErrNoSender):
		return "sender_missing"
	case errors.Is(err, ErrUnsupportedChannel):
		return "unsupported_channel"
	case errors.Is(err, ErrInvalidTarget):
		return "invalid_target"
	case errors.Is(err, ErrStore):
		return "store_error"
	case errors.Is(err, ErrProvider):
		return "provider_error"
	case errors.Is(err, ErrTokenInvalid):
		return "invalid_token"
	case errors.Is(err, ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, ErrTokenUsed):
		return "token_used"
	case errors.Is(err, ErrClosed):
		return "closed"
	case errors.Is(err, ErrInvalidType):
		return "invalid_type"
	case errors.Is(err, ErrInvalidOptions):
		return "invalid_options"
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, ErrRequestTooLarge):
		return "request_too_large"
	case errors.Is(err, ErrOriginNotAllowed):
		return "origin_not_allowed"
	default:
		return "internal_error"
	}
}
