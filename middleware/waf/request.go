package waf

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/shibingli/ydx/buffpool"
	"github.com/shibingli/ydx/errs"
)

// requestBodyChunkSize is the pooled read buffer used while feeding Coraza. | requestBodyChunkSize
// 是向 Coraza 喂正文时使用的池化读取缓冲大小。
const requestBodyChunkSize = 32 << 10

// processRequest feeds the connection, URI, headers and body into the transaction. It mirrors
// Coraza's official net/http adapter so that CRS rules observing Host, Transfer-Encoding and
// the replayed body keep working. | processRequest 把连接、URI、请求头与正文送入事务。它与
// Coraza 官方 net/http 适配器保持一致，使依赖 Host、Transfer-Encoding 与回放正文的 CRS 规则
// 继续生效。
func processRequest(tx types.Transaction, r *http.Request, client string, readBody bool) (*types.Interruption, error) {
	_, port := splitRemoteAddr(r.RemoteAddr)
	tx.ProcessConnection(client, port, "", 0)
	// RequestURI is the raw request target exactly as received and already allocated by
	// net/http; URL.String() would allocate a normalized copy on every request. Client-side
	// requests have no RequestURI, so fall back to the URL. | RequestURI 是 net/http 已分配的
	// 原始请求目标；URL.String() 会为每个请求分配一份规范化副本。客户端请求没有 RequestURI，
	// 因此回退到 URL。
	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.String()
	}
	tx.ProcessURI(uri, r.Method, r.Proto)
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	// net/http promotes Host out of Header; Coraza rules still expect it. | net/http 把 Host
	// 从 Header 中提出，但 Coraza 规则仍然需要它。
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	// net/http removes Transfer-Encoding from Header as well. | net/http 同样会移除
	// Transfer-Encoding。
	for _, encoding := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", encoding)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	// CONNECT carries a tunnel or an extended-CONNECT byte stream, never a bounded request body:
	// buffering it would consume the tunnel and stall the connection. readBody is false when no
	// rule in phases 2-5 can observe the request body, so the handler receives the raw stream. |
	// CONNECT 携带的是隧道或 extended-CONNECT 字节流，而不是有界请求正文；缓冲它会消费隧道并
	// 阻塞连接。没有 phase 2-5 规则能观察请求正文时 readBody 为 false，处理器直接拿到原始流。
	if readBody && r.Method != http.MethodConnect && tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, err := bufferRequestBody(tx, r)
		if err != nil {
			return nil, err
		}
		if it != nil {
			return it, nil
		}
	}
	return tx.ProcessRequestBody()
}

// bufferRequestBody feeds the request body into Coraza through a pooled chunk buffer instead of
// letting ReadRequestBodyFrom allocate an io.Copy buffer for every request. It replays exactly
// what Coraza buffered plus any chunk tail the body limit left unwritten. | bufferRequestBody
// 通过池化块缓冲把请求正文送入 Coraza，避免 ReadRequestBodyFrom 为每个请求分配 io.Copy 缓冲。
// 它按 Coraza 已缓冲的内容加上达到上限时未写入的块尾进行回放。
func bufferRequestBody(tx types.Transaction, r *http.Request) (*types.Interruption, error) {
	buf := buffpool.Get(requestBodyChunkSize)
	buf = buf[:requestBodyChunkSize]
	used := 0
	defer func() {
		// Body data may contain credentials; do not leave it for the next borrower. | 正文可能
		// 包含凭据，不能留给下一个借用者。
		clear(buf[:used])
		buffpool.Put(buf)
	}()
	for {
		n, readErr := r.Body.Read(buf)
		if n > used {
			used = n
		}
		if n > 0 {
			it, written, err := tx.WriteRequestBody(buf[:n])
			if it != nil {
				return it, nil
			}
			if err != nil {
				return nil, errs.Wrap(err, ErrRequestBody)
			}
			if written < n {
				// The limit was reached: Coraza kept the prefix; replay the rest of this chunk
				// before the untouched request body. | 达到上限：Coraza 保留了前缀，先把本块剩余
				// 部分接在回放流里，再接原始请求正文。
				tail := append([]byte(nil), buf[written:n]...)
				reader, readerErr := tx.RequestBodyReader()
				if readerErr != nil {
					return nil, errs.Wrap(readerErr, ErrRequestBody)
				}
				r.Body = io.NopCloser(io.MultiReader(reader, bytes.NewReader(tail), r.Body))
				return nil, nil
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, errs.Wrap(readErr, ErrRequestBody)
		}
	}
	reader, err := tx.RequestBodyReader()
	if err != nil {
		return nil, errs.Wrap(err, ErrRequestBody)
	}
	r.Body = io.NopCloser(io.MultiReader(reader, r.Body))
	return nil, nil
}

// splitRemoteAddr splits a net/http RemoteAddr value into host and port. The last colon is used
// so bracketed IPv6 addresses survive. | splitRemoteAddr 把 net/http 的 RemoteAddr 拆成主机与端口。
// 使用最后一个冒号，从而保留带方括号的 IPv6 地址。
func splitRemoteAddr(addr string) (string, int) {
	index := strings.LastIndexByte(addr, ':')
	if index < 0 {
		return addr, 0
	}
	port, err := strconv.Atoi(addr[index+1:])
	if err != nil {
		port = 0
	}
	return addr[:index], port
}

// clientIP returns the address reported to Coraza. | clientIP 返回报告给 Coraza 的地址。
func clientIP(o Options, r *http.Request) string {
	if o.ClientIP != nil {
		return o.ClientIP(r)
	}
	host, _ := splitRemoteAddr(r.RemoteAddr)
	return host
}

// requestErrorStatus maps an inspection failure to the response status. A body that exceeds the
// router's or WAF's byte limit is a client error, not a server error. | requestErrorStatus 把检测
// 失败映射为响应状态。超过路由器或 WAF 字节上限的正文属于客户端错误，而不是服务端错误。
func requestErrorStatus(err error) int {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusInternalServerError
}
