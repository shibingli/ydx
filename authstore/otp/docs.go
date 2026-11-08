// Package otp implements the auth/mfa/otp ReplayGuard on Redis.
// | Package otp 在 Redis 上实现 auth/mfa/otp 的 ReplayGuard。
//
// New returns a ReplayGuard that can be passed to otp.WithVerifierGuard. Every application
// instance that shares the same Redis deployment then shares the accepted (key, step) pairs, so a
// one-time code accepted by one instance is rejected by every other instance. The go-redis
// universal client passed to New stays owned by the caller and must be closed by the caller. New
// performs no network round trip. | New 返回可传给 otp.WithVerifierGuard 的 ReplayGuard。共享同一
// Redis 部署的所有应用实例随后共享已接受的 (key, step) 键值对，因此一个实例接受的一次性口令会被
// 其它所有实例拒绝。传给 New 的 go-redis 通用客户端始终归调用方所有，调用方必须关闭它。New 不进行
// 网络往返。
//
// # Multi-instance semantics | 多实例语义
//
// Accept is one Redis SET NX PX command, so for a fresh (key, step) pair exactly one concurrent
// caller across all instances receives true. The TTL has the same meaning as in the in-memory
// guard: the pair stays rejected until the TTL elapses and can be accepted again afterwards.
// Backend failures are reported as otp.ErrReplayStore and never expose the Redis address. |
// Accept 是单条 Redis SET NX PX 命令，因此对全新 (key, step) 键值对，所有实例的并发调用中只有一个
// 收到 true。TTL 与内存保护器含义相同：键值对在 TTL 经过前保持被拒绝，之后可再次被接受。后端故障
// 以 otp.ErrReplayStore 报告，且绝不暴露 Redis 地址。
//
// # Redis key layout | Redis 键布局
//
// Keys carry the shared hash tag so a cluster routes every key to one slot. The configurable
// prefix comes first and must not contain '{' or '}'. The key and step use a length-prefixed
// segment, so concatenation stays unambiguous. With the default prefix "ydx:authstore:otp:" the
// layout is: | 键携带共享哈希标签，使集群把每个键路由到单一槽位。可配置前缀位于最前，且不得包含
// '{' 或 '}'。键与步使用长度前缀段，因此拼接始终无歧义。默认前缀 "ydx:authstore:otp:" 下的布局为：
//
//	ydx:authstore:otp:{authstore:otp}:replay:<len>:<key>:<step>
//	                                                       string "1", expiry = TTL | 字符串 "1"，期限为 TTL
//
// # YD router | YD 路由
//
// Pass the guard to the verifier and verify the submitted code in a handler: |
// 把保护器传给校验器，并在处理器中校验提交的口令：
//
//	guard, err := otpstore.New(client, otpstore.Options{})
//	if err != nil {
//		return err
//	}
//	verifier := otp.NewVerifier(otp.WithVerifierGuard(guard))
//	r.HandleRaw(http.MethodPost, "/mfa/verify", func(w http.ResponseWriter, req *http.Request) {
//		code := req.FormValue("code")
//		if _, ok, err := verifier.ValidateTOTP(req.Context(), secret, code); err != nil || !ok {
//			http.Error(w, "unauthorized", http.StatusUnauthorized)
//			return
//		}
//		w.WriteHeader(http.StatusNoContent)
//	})
//
// # Native net/http | 原生 net/http
//
// The same guard works without the YD router, because it depends only on context and native Go
// values: | 同一个保护器无需 YD 路由即可工作，因为它只依赖上下文与原生 Go 值：
//
//	guard, err := otpstore.New(client, otpstore.Options{})
//	if err != nil {
//		return err
//	}
//	verifier := otp.NewVerifier(otp.WithVerifierGuard(guard))
//	mux := http.NewServeMux()
//	mux.HandleFunc("POST /mfa/verify", func(w http.ResponseWriter, req *http.Request) {
//		code := req.FormValue("code")
//		if _, ok, err := verifier.ValidateTOTP(req.Context(), secret, code); err != nil || !ok {
//			http.Error(w, "unauthorized", http.StatusUnauthorized)
//			return
//		}
//		w.WriteHeader(http.StatusNoContent)
//	})
//
// Deployments with a single process may keep otp.NewMemoryReplayGuard; select this package only
// when several instances must share replay state. | 单进程部署可以继续使用
// otp.NewMemoryReplayGuard；仅在多个实例必须共享重放状态时选用本包。
package otp
