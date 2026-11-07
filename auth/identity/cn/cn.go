// Package cn provides mainland-China identity and contact helpers for the ydx auth toolkit:
// mobile-number normalization and carrier lookup, resident identity card parsing (GB 11643-1999),
// unified social credit code validation (GB 32100-2015), bank-card masking and Luhn validation,
// Chinese name and email masking, real-name verification adapters and SMS one-time-password login.
// | Package cn 提供 ydx 认证工具集的中国大陆身份与联系方式辅助能力：手机号规范化与运营商识别、
// 居民身份证解析（GB 11643-1999）、统一社会信用代码校验（GB 32100-2015）、银行卡掩码与 Luhn
// 校验、中文姓名与邮箱掩码、实名认证适配器，以及短信一次性验证码登录。
//
// The validators check syntax, checksums and documented region/prefix tables. They are not an
// authoritative identity check: a structurally valid number does not prove that the document exists
// or belongs to the caller. Use RealNameVerifier for authoritative verification and keep raw
// identity values out of logs and error messages. | 这些校验器只检查语法、校验码以及文档化的
// 地区/号段表，并不构成权威身份核验：结构合法的号码不能证明证件真实存在或属于调用方。权威核验请
// 使用 RealNameVerifier，并避免把身份原文写入日志或错误文案。
//
// Mobile numbers are normalized to E.164 form (+86...). Identity card numbers are normalized to the
// 18-character form, upgrading legacy 15-digit numbers with the documented 19xx rule. | 手机号统一
// 规范化为 E.164（+86...）。身份证号统一规范化为 18 位形式，15 位旧号码按文档化的 19xx 规则升级。
//
// # Example | 示例
//
//	mobile, err := cn.NormalizeMobile("+86 138-0013-8000") // "+8613800138000"
//	carrier, err := cn.Carrier(mobile)                    // cn.CarrierChinaMobile
//	card, err := cn.ParseIDCard("11010519491231002X")     // Valid, 1949-12-31, female
//	ok := cn.ValidateUnifiedSocialCreditCode("91350100M000100Y43")
//	masked := cn.MaskMobile(mobile)                       // "138****8000"
//
// # HTTP entries | HTTP 入口
//
// HTTPVerifier and HTTPProvider are plain net/http clients and work with or without ydx/router; they
// are configured with a URL and optional header/signing hooks, so no vendor credential is hardcoded. |
// HTTPVerifier 与 HTTPProvider 是标准 net/http 客户端，可与 ydx/router 配合使用也可独立使用；它们
// 通过 URL 与可选的请求头/签名钩子配置，不硬编码任何厂商凭据。
package cn

import (
	"github.com/shibingli/ydx/errs"
)

// The shared sentinels of the package. | 本包的共享哨兵错误。
//
// Domain-specific sentinels are declared next to their validators. Every failure path returns one of
// them directly or through errs.Detail / errs.Wrap, so callers classify errors with errors.Is and
// never have to match message text. | 领域专用哨兵声明在各自的校验器旁。所有失败路径都直接返回其中
// 之一或经 errs.Detail / errs.Wrap 包装，调用方用 errors.Is 分类而无需匹配文案。
var (
	// ErrInvalidConfig reports a missing or contradictory configuration. | ErrInvalidConfig 表示配置缺失或互相矛盾。
	ErrInvalidConfig = errs.New("cn: invalid configuration | cn：配置非法")
	// ErrInvalidRequest reports malformed caller input that is not covered by a more specific sentinel. | ErrInvalidRequest 表示未被更具体哨兵覆盖的调用方输入非法。
	ErrInvalidRequest = errs.New("cn: invalid request | cn：请求非法")
)
