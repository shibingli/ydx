package oidc

import (
	"net/http"

	"github.com/shibingli/ydx/router"
)

// Register mounts the OpenID Provider endpoints on a ydx/router Router. | Register 把 OpenID 提供方端点挂载到 ydx/router Router。
//
// The OAuth endpoints are mounted separately by oauth2.Server.Register; mounting both is the normal
// composition. | OAuth 端点由 oauth2.Server.Register 单独挂载；同时挂载两者是常规组合。
func (p *Provider) Register(r *router.Router) {
	if r == nil {
		return
	}
	r.HandleRaw(http.MethodGet, p.Path(p.config.DiscoveryPath), p.Discovery)
	r.HandleRaw(http.MethodGet, p.Path(p.config.JWKSPath), p.JWKS)
	r.HandleRaw(http.MethodGet, p.Path(p.config.UserInfoPath), p.UserInfo)
	r.HandleRaw(http.MethodPost, p.Path(p.config.UserInfoPath), p.UserInfo)
	if p.config.EnableLogout {
		r.HandleRaw(http.MethodGet, p.Path(p.config.EndSessionPath), p.EndSession)
		r.HandleRaw(http.MethodPost, p.Path(p.config.EndSessionPath), p.EndSession)
	}
	if p.config.SessionManagement {
		r.HandleRaw(http.MethodGet, p.Path(p.config.CheckSessionPath), p.CheckSession)
	}
	if p.config.FrontchannelLogout {
		r.HandleRaw(http.MethodGet, p.Path(p.config.FrontchannelLogoutPath), p.FrontchannelLogout)
	}
	if p.config.BackchannelLogout {
		r.HandleRaw(http.MethodPost, p.Path(p.config.BackchannelLogoutPath), p.BackchannelLogout)
	}
	if p.config.EnableRegistration {
		r.HandleRaw(http.MethodPost, p.Path(p.config.RegistrationPath), p.RegisterClient)
		management := p.Path(p.config.RegistrationPath) + "/:client_id"
		handler := func(c *router.Ctx) { p.ClientConfiguration(c.Writer, c.Request) }
		r.Handle(http.MethodGet, management, handler)
		r.Handle(http.MethodPut, management, handler)
		r.Handle(http.MethodDelete, management, handler)
	}
}

// HTTPHandler returns a complete net/http handler for every OpenID Provider endpoint. | HTTPHandler
// 返回包含全部 OpenID 提供方端点的 net/http 处理器。
func (p *Provider) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(p.Path(p.config.DiscoveryPath), p.Discovery)
	mux.HandleFunc(p.Path(p.config.JWKSPath), p.JWKS)
	mux.HandleFunc(p.Path(p.config.UserInfoPath), p.UserInfo)
	if p.config.EnableLogout {
		mux.HandleFunc(p.Path(p.config.EndSessionPath), p.EndSession)
	}
	if p.config.SessionManagement {
		mux.HandleFunc(p.Path(p.config.CheckSessionPath), p.CheckSession)
	}
	if p.config.FrontchannelLogout {
		mux.HandleFunc(p.Path(p.config.FrontchannelLogoutPath), p.FrontchannelLogout)
	}
	if p.config.BackchannelLogout {
		mux.HandleFunc(p.Path(p.config.BackchannelLogoutPath), p.BackchannelLogout)
	}
	if p.config.EnableRegistration {
		mux.HandleFunc(p.Path(p.config.RegistrationPath), p.RegisterClient)
		prefix := p.Path(p.config.RegistrationPath) + "/"
		mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			p.ClientConfiguration(w, r)
		})
	}
	return mux
}
