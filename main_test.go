package main

import (
	"github.com/dgrijalva/jwt-go"
	. "github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"github.com/learnfromgirls/loginsrv/logging"
	"github.com/tarent/logrus"
)

func Test_BasicEndToEnd(t *testing.T) {
	logging.Logger.Level = logrus.InfoLevel

	//can create tmp file
	d1 := []byte("dummy:secret\n")
	err3 := ioutil.WriteFile("/tmp/.htpasswd", d1, 0644)
	NoError(t, err3)

	originalArgs := os.Args

	secret := "theSecret"
	os.Args = []string{"loginsrv", "-jwt-secret", secret, "-host=localhost", "-port=3000", "-simple=bob=secret", "-htpasswd=files=/tmp/.htpasswd"}
	defer func() { os.Args = originalArgs }()

	go main()

	time.Sleep(time.Second)

	// success
	req, err := http.NewRequest("POST", "http://localhost:3000/login", strings.NewReader(`{"username": "bob", "password": "secret"}`))
	NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/jwt")
	r, err := http.DefaultClient.Do(req)
	NoError(t, err)

	Equal(t, 200, r.StatusCode)
	Equal(t, "application/jwt", r.Header.Get("Content-Type"))

	b, err := ioutil.ReadAll(r.Body)
	NoError(t, err)

	token, err := jwt.Parse(string(b), func(*jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	NoError(t, err)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		Equal(t, "bob", claims["sub"])
	} else {
		t.Fail()
	}
	subArgon2unseal(t)
}

func subArgon2unseal(t *testing.T) {
	secret := "theSecret"

	// success
	req, err := http.NewRequest("POST", "http://localhost:3000/login", strings.NewReader(`{"username": "vault", "password": "secret"}`))
	NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/jwt")
	r, err := http.DefaultClient.Do(req)
	NoError(t, err)

	Equal(t, 200, r.StatusCode)
	Equal(t,  "application/jwt", r.Header.Get("Content-Type"))

	b, err := ioutil.ReadAll(r.Body)
	NoError(t, err)

	token, err := jwt.Parse(string(b), func(*jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	NoError(t, err)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		Equal(t, "vault", claims["sub"])
	} else {
		t.Fail()
	}
}
