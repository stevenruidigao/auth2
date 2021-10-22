package database

import (
	//	"encoding/binary"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

type MFAOptions struct {
	TOTP     bool
	Webauthn bool
}

type User struct {
	Data          string
	ID            string
	Name          string
	Username      string
	Enabled       MFAOptions
	Email         string
	PhoneNumber   string
	PasswordHash  string
	Salt          string
	Success       bool
	Token         string
	TokenExpires  time.Time
	Required      int
	TOTP          string
	TOTPSecret    string
	WADisplayName string
	WAIcon        string
	WAID          []byte
	WACredentials []webauthn.Credential
}

func (user User) CredentialExcludeList() []protocol.CredentialDescriptor {
	credentialExcludeList := []protocol.CredentialDescriptor{}

	for _, cred := range user.WACredentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}

		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

func (user *User) WebAuthnCredentials() []webauthn.Credential {
	return user.WACredentials
}

func (user *User) WebAuthnDisplayName() string {
//	return "New User"
	//	return user.Name
		return user.Username
}

func (user *User) WebAuthnIcon() string {
	return user.WAIcon
}

func (user *User) WebAuthnID() []byte {
	return []byte(user.ID)
	//	return user.WAID
}

func (user *User) WebAuthnName() string {
	return user.Username
}
