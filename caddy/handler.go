package caddy

import (
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/learnfromgirls/loginsrv/login"
	"net/http"
	"strings"
)

// CaddyHandler is the loginsrv handler wrapper for caddy
type CaddyHandler struct {
	next         httpserver.Handler
	config       *login.Config
	loginHandler *login.Handler
}

// NewCaddyHandler create the handler
func NewCaddyHandler(next httpserver.Handler, loginHandler *login.Handler, config *login.Config) *CaddyHandler {
	h := &CaddyHandler{
		next:         next,
		config:       config,
		loginHandler: loginHandler,
	}
	return h
}

func (h *CaddyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if strings.HasPrefix(r.URL.Path, h.config.LoginPath) {
		h.loginHandler.ServeHTTP(w, r)
		return 0, nil
	}
	return h.next.ServeHTTP(w, r)
}
