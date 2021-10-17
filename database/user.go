package database

import (
	//	"encoding/binary"
	"time"

	"github.com/duo-labs/webauthn/webauthn"
)

type User struct {
	ID            string
	Name          string
	Username      string
	Email         string
	PhoneNumber   string
	PasswordHash  string
	Salt          string
	Success       bool
	Token         string
	TokenExpires  time.Time
	WADisplayName string
	WAIcon        string
	WAID          []byte
	WACredentials []webauthn.Credential
}

func (user *User) WebAuthnCredentials() []webauthn.Credential {
	return user.WACredentials
}

func (user *User) WebAuthnDisplayName() string {
	return "New User"
//	return user.Name
}

func (user *User) WebAuthnIcon() string {
	return user.WAIcon
}

func (user *User) WebAuthnID() []byte {
	return []byte(user.ID)
	//	return user.WAID
}

func (user *User) WebAuthnName() string {
	return user.Name
}
