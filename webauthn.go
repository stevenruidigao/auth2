package main

import (
	"fmt"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"

	"authenticate/database"
	"authenticate/utils"
)

func BeginWebauthnRegistration(writer http.ResponseWriter, request *http.Request) {
	user, _ := Authenticate(request)

	if user == nil {
		fmt.Println(user)
		utils.JSONResponse(writer, Message{Success: false, Message: "You need to log in first."}, http.StatusUnauthorized)
		return
	}

	registerOptions := func(credentialCreationOptions *protocol.PublicKeyCredentialCreationOptions) {
		credentialCreationOptions.CredentialExcludeList = user.CredentialExcludeList()
	}

	options, sessionData, err := webAuthn.BeginRegistration(user, registerOptions)

	if err != nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
		return
	}

	err = sessionStore.SaveWebauthnSession("registration", sessionData, request, writer)

	if err != nil {
		fmt.Println(err)
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
		return
	}

	utils.JSONResponse(writer, options, http.StatusOK)
}

func FinishWebauthnRegistration(writer http.ResponseWriter, request *http.Request) {
	user, _ := Authenticate(request)

	if user == nil {
		fmt.Println(user)
		utils.JSONResponse(writer, Message{Success: false, Message: "You need to log in first."}, http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", request)

	if err != nil {
		fmt.Println(err)
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, request)

	if err != nil {
		fmt.Println(err)
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusBadRequest)
		return
	}

	user.WACredentials = append(user.WACredentials, *credential)
	user.Enabled.Webauthn = true
	user.Required = 2
	database.UpdateUser(user, userDatabase)
	utils.JSONResponse(writer, Message{Success: true, Message: "Webauthn credential successfully registered."}, http.StatusOK)
	return
}
