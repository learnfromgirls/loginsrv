package login

import (
	"github.com/learnfromgirls/safesecrets"
	"github.com/tarent/loginsrv/model"
)

// Backend is an loginsrv authentication extension
type Backend interface {
	// Authenticate checks the username/password against the backend.
	// On success it returns true and a UserInfo object which has at least the username set.
	// If the credentials do not match, false is returned.
	// The error parameter is nil, unless a communication error with the backend occurred.
	Authenticate(username, password string, ssa ...safesecrets.SecretSetter) (bool, model.UserInfo, error)
}
