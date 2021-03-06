package htpasswd

import (
	"bytes"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"github.com/abbot/go-http-auth"
	"github.com/learnfromgirls/argon2-go-withsecret"
	"github.com/learnfromgirls/safesecrets"

	"github.com/tarent/loginsrv/logging"
	"golang.org/x/crypto/bcrypt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"io/ioutil"
)

// File is a struct to serve an individual modTime
type File struct {
	name    string
	// Used in func reloadIfChanged to reload htpasswd file if it changed
	modTime time.Time
}

// Auth is the htpassword authenticater
type Auth struct {
	filenames    []File
	userHash     map[string]string
	muUserHash   sync.RWMutex
	argonContext *argon2_go_withsecret.Context
	unsealed     bool
	bootstrapped bool
}

// NewAuth creates an htpassword authenticater
func NewAuth(filenames []string) (*Auth, error) {
	var htpasswdFiles []File
	for _, file := range filenames {
		htpasswdFiles = append(htpasswdFiles, File{name: file})
	}

	ac := argon2_go_withsecret.NewContext()
	ac.SetMemory(1 << uint(18)) //256Mbytes so will fit on a nano EC2
	ac.SetIterations(20) //20 times as slow. This is the master password used to derive the secret
	// so will only be used once per boot
	//initially no secret so we must protect against guessing.

	a := &Auth{
		filenames: htpasswdFiles,
		argonContext : ac,
		unsealed: false,
		bootstrapped: false,
	}
	return a, a.parse(htpasswdFiles)
}

func (a *Auth) parse(filenames []File) error {
	tmpUserHash := map[string]string{}

	for _, filename := range a.filenames {
		r, err := os.Open(filename.name)
		if err != nil {
			return err
		}

		fileInfo, err := os.Stat(filename.name)
		if err != nil {
			return err
		}
		filename.modTime = fileInfo.ModTime()

		cr := csv.NewReader(r)
		cr.Comma = ':'
		cr.Comment = '#'
		cr.TrimLeadingSpace = true

		for {
			record, err := cr.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if len(record) != 2 {
				return fmt.Errorf("password file in wrong format (%v)", filename)
			}

			if _, exist := tmpUserHash[record[0]]; exist {
				logging.Logger.Warnf("Found duplicate entry for user: (%v)", record[0])
			}
			tmpUserHash[record[0]] = record[1]
		}
	}
	a.muUserHash.Lock()
	a.userHash = tmpUserHash
	a.muUserHash.Unlock()

	return nil
}

// Authenticate the user
func (a *Auth) Authenticate(username, password string, ssa ...safesecrets.SecretSetter) (bool, error) {
	reloadIfChanged(a)
	a.muUserHash.RLock()
	defer a.muUserHash.RUnlock()
	vaultUser := "vault"
	logging.Logger.Infof("Authenticating htpasswd for user: (%v)", username)
	if hash, exist := a.userHash[username]; exist {
		logging.Logger.Infof("htpasswd for user: (%v) exists. hash: (%v)", username, hash)
		h := []byte(hash)
		p := []byte(password)
		if strings.HasPrefix(hash, "$2y$") || strings.HasPrefix(hash, "$2b$") {
			matchErr := bcrypt.CompareHashAndPassword(h, p)
			return (matchErr == nil), nil
		}
		if strings.HasPrefix(hash, "{SHA}") {
			return compareSha(h, p), nil
		}
		if strings.HasPrefix(hash, "$apr1$") {
			return compareMD5(h, p), nil
		}
		verySecurePrefix := "$argon2id$v=19$m=262144,t=20,p=2$"
		argonPrefix := "$argon2"

		if strings.HasPrefix(hash, argonPrefix) {
			verified, err := a.argonContext.VerifyEncoded(hash, p)
			//special case
			if a.unsealed == false && verified && err == nil && username == vaultUser && strings.HasPrefix(hash, verySecurePrefix) {
				kdfinputp := "slightlydifferent" + password;
				kdfinputsalt := "wellknownsaltfor"
				//prefer not to use same instance for hash and verify
				//we expect attacker to know salt and password modifier so do have a good password.
				//attacker will be guessing but will be thwarted by the extra hard argon2 parameters.
				ach := argon2_go_withsecret.NewVaultContext()

				derivedSecret, err2 := ach.Hash([]byte(
					kdfinputp), []byte(
					kdfinputsalt))
				if err2 == nil {
					a.argonContext.SetSecret(derivedSecret)
					jwtinputsalt := "othwellknown1234"
					err3 := ach.SetSecrets([] byte(kdfinputp), []byte(jwtinputsalt), ssa...)
					a.unsealed = true
					if err3 != nil {
						logging.Logger.Errorf("htpasswd argon err setting secrets (%v)", err3)
					}
				} else {
					return verified, err2
				}
			}
			logging.Logger.Infof("htpasswd argon returning (%v)", verified)
			return verified, err
		}

		return false, fmt.Errorf("unknown algorithm for user %q", username)
	} else {
		//user does not exist
		logging.Logger.Infof("htpasswd for user: (%v) not exists.", username)
		//special case
		if a.unsealed == false && a.bootstrapped == false && username == vaultUser {
			logging.Logger.Infof("htpasswd for user is vaultUser and unsealed is false")
			//bootstrap. create a user in /tmp/.htpasswd
			vaultp := password;
			salt, err := argon2_go_withsecret.NewRandomSalt()
			if err == nil {
				logging.Logger.Infof("htpasswd got random salt")
				//prefer not to use same instance for hash and verify
				//we expect attacker to know salt and password modifier so do have a good password.
				//attacker will be guessing but will be thwarted by the extra hard argon2 parameters.
				ach := argon2_go_withsecret.NewContext()
				ach.SetMemory(1 << uint(18)) //256Mbytes so will fit on a nano EC2
				ach.SetIterations(20) //20 times not default 3.
				vhash, err2 := ach.HashEncoded([] byte(vaultp), salt)
				if err2 == nil {
					logging.Logger.Infof("htpasswd got vhash (%v)", vhash)
					outstr := vaultUser + ":" + vhash + "\n"
					d1 := []byte(outstr)
					err3 := ioutil.WriteFile("/tmp/.htpasswd", d1, 0644)
					if err3 == nil {
						logging.Logger.Infof("htpasswd wrote file wth no error returning true")
						a.bootstrapped = true //make this bootstrap a one off
						return true, nil
					} else {
						logging.Logger.Infof("htpasswd failed writing file err (%v)", err3)
						return false, err3
					}

				} else {
					logging.Logger.Infof("htpasswd error with hashencoding err (%v)", err2)
					return false, err2
				}
			} else {
				logging.Logger.Infof("htpasswd failed to get random salt err (%v)", err)
				return false, err
			}
		}
	}
	logging.Logger.Infof("htpasswd returning false")
	return false, nil
}

// Reload htpasswd file if it changed during current run
func reloadIfChanged(a *Auth) {
	for _, file := range a.filenames {
		fileInfo, err := os.Stat(file.name)
		if err != nil {
			//On error, retain current file
			break
		}
		currentmodTime := fileInfo.ModTime()
		if currentmodTime != file.modTime {
			a.parse(a.filenames)
			return
		}
	}
}

func compareSha(hashedPassword, password []byte) bool {
	d := sha1.New()
	d.Write(password)
	return 1 == subtle.ConstantTimeCompare(hashedPassword[5:], []byte(base64.StdEncoding.EncodeToString(d.Sum(nil))))
}

func compareMD5(hashedPassword, password []byte) bool {
	parts := bytes.SplitN(hashedPassword, []byte("$"), 4)
	if len(parts) != 4 {
		return false
	}
	magic := []byte("$" + string(parts[1]) + "$")
	salt := parts[2]
	return 1 == subtle.ConstantTimeCompare(hashedPassword, auth.MD5Crypt(password, salt, magic))
}
