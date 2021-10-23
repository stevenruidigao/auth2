package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"authenticate/database"
	"authenticate/utils"
)

func Login(writer http.ResponseWriter, request *http.Request) {
	valid := 0
	body := utils.ReadRequestBody(request)
	var credentials database.User
	err := json.Unmarshal(body, &credentials)

	if err != nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusOK)
		return
	}

	user := database.FindUser(&database.User{Username: credentials.Username}, userDatabase)

	if user == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, http.StatusUnauthorized)
		return

	} else if !user.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
		return

	} else if credentials.PasswordHash != "" {
		credentials.PasswordHash = utils.Argon2(credentials.PasswordHash, user.Salt)

		if credentials.PasswordHash != user.PasswordHash {
			utils.JSONResponse(writer, Message{Success: false, Message: "That password was incorrect."}, http.StatusUnauthorized)
			return

		} else {
			valid++
		}
	}

	if credentials.TOTP != "" {
		if totp.Validate(credentials.TOTP, user.TOTPSecret) {
			valid++
		}
	}

	sessionData, err := sessionStore.GetWebauthnSession("authentication", request)

	if err != nil {
		fmt.Println(err)
		//      utils.JSONResponse(writer, err.Error(), http.StatusBadRequest)
		//      return

	} else {
		// in an actual implementation we should perform additional
		// checks on the returned 'credential'

		credential, err := webAuthn.FinishLogin(user, sessionData, request)

		if err != nil {
			fmt.Println(err)
			//      utils.JSONResponse(writer, err.Error(), http.StatusBadRequest)

		} else {
			if credential.Authenticator.CloneWarning {
				fmt.Println("credential appears to be cloned: %s", err)
				utils.JSONResponse(writer, Message{Success: false, Message: "Credential appears to be cloned."}, http.StatusForbidden)
				return
			}

			var i int

			for i = range user.WACredentials {
				if bytes.Equal(user.WACredentials[i].ID, credential.ID) {
					fmt.Println("*", i)
					break
				}
			}

			user.WACredentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
			database.UpdateUser(user, userDatabase)
			valid++
		}
	}

	fmt.Println("auth2", valid, user.Required)

	if valid >= user.Required {
		authenticated, token := Authenticate(request)

		if token == nil || time.Since(token.TokenExpires) > 0 {
			user.Token = uuid.NewString()
			user.TokenExpires = time.Now().Add(24 * time.Hour)
			user.Tokens = append(user.Tokens, database.Token{TokenHash: utils.SHA512(user.Token), TokenExpires: user.TokenExpires})
			database.UpdateUser(user, userDatabase)
			utils.AddCookie(writer, "token", user.Token, time.Until(user.TokenExpires))

		} else if authenticated == nil || authenticated.ID != user.ID {
			utils.AddCookie(writer, "token", user.Token, time.Until(user.TokenExpires))
		}

		utils.JSONResponse(writer, Message{Success: true, Message: "You logged in successfully."}, http.StatusOK)

	} else if user.Enabled.Webauthn {
		options, sessionData, err := webAuthn.BeginLogin(user)

		if err != nil {
			fmt.Println(err)
			utils.JSONResponse(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		// store session data as marshaled JSON
		err = sessionStore.SaveWebauthnSession("authentication", sessionData, request, writer)

		if err != nil {
			fmt.Println(err)
			utils.JSONResponse(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonOptions, err := json.Marshal(options)

		if err != nil {
			fmt.Println(err)
			utils.JSONResponse(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonMFAData, err := json.Marshal(MFAData{Enabled: user.Enabled, Required: user.Required, Webauthn: string(jsonOptions)})

		if err != nil {
			fmt.Println(err)
			utils.JSONResponse(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		utils.JSONResponse(writer, Message{Success: false, Message: "MFA Required.", Data: string(jsonMFAData)}, http.StatusForbidden)

	} else {
		utils.JSONResponse(writer, Message{Success: false, Message: "MFA Required."}, http.StatusForbidden)
	}
}
