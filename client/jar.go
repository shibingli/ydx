package client

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync/atomic"
)

// lazyJar avoids cookie lookups until the first Set-Cookie. | lazyJar 在首次 Set-Cookie 前跳过 Cookie 查找。
type lazyJar struct {
	jar    http.CookieJar
	active atomic.Bool
}

// newLazyJar builds the default in-memory lazy cookie jar. | newLazyJar 构建默认内存惰性 Cookie 罐。
func newLazyJar() *lazyJar {
	jar, _ := cookiejar.New(nil)
	return &lazyJar{jar: jar}
}

// Cookies returns no cookies until the jar has stored one. | Cookies 在存储 Cookie 前返回空。
func (j *lazyJar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil || !j.active.Load() {
		return nil
	}
	return j.jar.Cookies(u)
}

// SetCookies enables the jar when non-empty cookies are stored. | SetCookies 在写入非空 Cookie 时启用罐。
func (j *lazyJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j == nil || len(cookies) == 0 {
		return
	}
	j.active.Store(true)
	j.jar.SetCookies(u, cookies)
}
