package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"authenticate/database"
	"authenticate/session"
	"authenticate/utils"
)

type MFAData struct {
	Enabled  database.MFAOptions `json:"enabled"`
	Required int                 `json:"required"`
	Webauthn string              `json:"webauthn"`
	TOTP     string              `json:"totp"`
}

type Message struct {
	Data    string `json:"data"`
	Message string `json:"message"`
	Success bool   `json:"success"`
}

type Visitor struct {
	Limiter  *rate.Limiter
	LastSeen time.Time
}

var sessionStore *session.Store
var userDatabase *mongo.Database
var visitors map[string]*Visitor
var visitorsMutex sync.Mutex
var webAuthn *webauthn.WebAuthn

func main() {
	DBHost := "127.0.0.1"
	DBPort := "27017"
	DBName := "authenticate"
	DBMaxPoolSize := "50"

	host := ""
	port := 8080

	var err error

	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Authenticate",
		RPID:          "localhost", //"authenticate.ands.ee",
		RPOrigin:      "",          //"https://authenticate.ands.ee",
		RPIcon:        "https://duo.com/logo.png",
	})

	if err != nil {
		fmt.Println(err)
	}

	sessionStore, err = session.NewStore()

	if err != nil {
		fmt.Println(err)
	}

	router := mux.NewRouter()
	apiRouter := mux.NewRouter().PathPrefix("/api").Subrouter()
	router.PathPrefix("/api").Handler(Limit(apiRouter))
	authRouter := apiRouter.PathPrefix("/auth").Subrouter()
	authRouter.Path("/login").Methods(http.MethodPost).HandlerFunc(Login)
	authRouter.Path("/register").Methods(http.MethodPost).HandlerFunc(Register)
	authRouter.Path("/register/totp").Methods(http.MethodPost).HandlerFunc(RegisterTOTP)
	registerWebauthnRouter := authRouter.PathPrefix("/register/webauthn").Subrouter()
	registerWebauthnRouter.Path("/begin").Methods(http.MethodPost).HandlerFunc(BeginWebauthnRegistration)
	registerWebauthnRouter.Path("/finish").Methods(http.MethodPost).HandlerFunc(FinishWebauthnRegistration)
	authRouter.Path("/salt").Methods(http.MethodPost).HandlerFunc(Salt)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	go CleanUpVisitors()

	uri := "mongodb://" + DBHost + ":" + DBPort + "/" + DBName + "?maxPoolSize=" + DBMaxPoolSize
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))

	if err != nil {
		panic(err)
	}

	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		panic(err)
	}

	userDatabase = client.Database(DBName)
	visitors = map[string]*Visitor{}

	fmt.Println("Listening on " + host + ":" + strconv.Itoa(port))
	http.ListenAndServe(host+":"+strconv.Itoa(port), router)
}

func Login(writer http.ResponseWriter, request *http.Request) {
	valid := 0
	body := utils.ReadRequestBody(request)
	var credentials database.User
	err := json.Unmarshal(body, &credentials)
	// err := json.NewDecoder(request.Body).Decode(&credentials)

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

	fmt.Println("auth")

	if err != nil {
		fmt.Println(err)
		//	utils.JSONResponse(writer, err.Error(), http.StatusBadRequest)
		//	return

	} else {
		// in an actual implementation we should perform additional
		// checks on the returned 'credential'

		credential, err := webAuthn.FinishLogin(user, sessionData, request)

		if err != nil {
			fmt.Println(err)
			//	utils.JSONResponse(writer, err.Error(), http.StatusBadRequest)

		} else {
			if credential.Authenticator.CloneWarning {
				fmt.Println("credential appears to be cloned: %s", err)
				utils.JSONResponse(writer, "", http.StatusForbidden)
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
		authenticated := Authenticate(request)

		if time.Since(user.TokenExpires) > 0 {
			user.Token = uuid.NewString()
			user.TokenExpires = time.Now().Add(24 * time.Hour)
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

	fmt.Println(user.Enabled)
}

func Register(writer http.ResponseWriter, request *http.Request) {
	var user database.User
	err := json.NewDecoder(request.Body).Decode(&user)

	if err != nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
		return
	}

	user.ID = uuid.NewString()
	user.PasswordHash = utils.Argon2(user.PasswordHash, user.Salt)
	result := database.RegisterUser(&user, userDatabase)

	if result != nil && !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An account with that name already exists."}, 403)

	} else if !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)

	} else {
		user.Token = uuid.NewString()
		user.TokenExpires = time.Now().Add(24 * time.Hour)
		database.UpdateUser(&user, userDatabase)
		utils.AddCookie(writer, "token", user.Token, time.Until(user.TokenExpires))
		utils.JSONResponse(writer, Message{Success: true, Message: "Your account was created successfully."}, http.StatusOK)
	}
}

func Salt(writer http.ResponseWriter, request *http.Request) {
	var user database.User
	json.NewDecoder(request.Body).Decode(&user)
	fmt.Println(user)
	result := database.FindUser(&database.User{Username: user.Username}, userDatabase)

	if result == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, http.StatusUnauthorized)

	} else if !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)

	} else {
		utils.JSONResponse(writer, Message{Success: true, Message: result.Salt}, http.StatusOK)
	}
}

func Authenticate(request *http.Request) *database.User {
	auth, err := request.Cookie("token")

	if err != nil {
		fmt.Println(err)
		return nil
	}

	fmt.Println(auth.Value)
	result := database.FindUser(&database.User{Token: auth.Value}, userDatabase)
	// result := database.FindUser(&database.User{Token: request.Header.Get("Bearer")}, userDatabase)

	if result == nil {
		return nil
	}

	return result
}

func RegisterTOTP(writer http.ResponseWriter, request *http.Request) {
	user := Authenticate(request)

	if user == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "You need to log in first."}, http.StatusUnauthorized)
		return
	}

	if user.TOTPSecret != "" {
		utils.JSONResponse(writer, Message{Success: false, Message: "You already have TOTP enabled."}, http.StatusUnauthorized)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Authenticate", AccountName: user.Username})

	if err != nil {
		fmt.Println(err)
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
		return
	}

	image, err := key.Image(512, 512)

	if err != nil {
		fmt.Println(err)
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	png.Encode(&buf, image)

	if err != nil {
		fmt.Println(err)
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
		return
	}

	utils.JSONResponse(writer, Message{Success: true, Message: "Your TOTP key was generated.", Data: key.Secret()}, http.StatusInternalServerError)
	fmt.Println(key, key.Secret(), image)
	user.Enabled.TOTP = true
	user.TOTPSecret = key.Secret()
	database.UpdateUser(user, userDatabase)
}

func BeginWebauthnRegistration(writer http.ResponseWriter, request *http.Request) {
	user := Authenticate(request)
	/*var user database.User
	json.NewDecoder(request.Body).Decode(&user)
	result := database.FindUser(&database.User{Username: user.Username}, userDatabase)*/
	// result := user //database.FindUser(&database.User{ID: user.ID}, userDatabase)

	/*if result == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, http.StatusInternalServerError)
		return
	}*/

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
	user := Authenticate(request)
	/*var user database.User
	bytes := utils.ReadRequestBody(request)
	json.Unmarshal(bytes, &user)
	result := database.FindUser(&database.User{Username: user.Username}, userDatabase)*/
	result := user //database.FindUser(&database.User{ID: user.ID}, userDatabase)

	/*if result == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusBadRequest)
		return
	}A

	authenticated := Authenticate(request)

	if authenticated == nil || result.ID != authenticated.ID {
		fmt.Println(authenticated, result)
		utils.JSONResponse(writer, Message{Success: false, Message: "You need to log in first."}, http.StatusUnauthorized)
		return
	}*/

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

	credential, err := webAuthn.FinishRegistration(result, sessionData, request)

	if err != nil {
		fmt.Println(err)
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusBadRequest)
		return
	}

	result.WACredentials = append(result.WACredentials, *credential)
	user.Enabled.Webauthn = true
	database.UpdateUser(result, userDatabase)
	utils.JSONResponse(writer, Message{Success: true, Message: "Webauthn credential successfully registered."}, http.StatusOK)
	return
}

func GetLimiter(hash string) *rate.Limiter {
	visitorsMutex.Lock()
	defer visitorsMutex.Unlock()

	visitor := visitors[hash]

	if visitor == nil {
		limiter := rate.NewLimiter(1, 5)
		visitors[hash] = &Visitor{limiter, time.Now()}
		return limiter
	}

	visitor.LastSeen = time.Now()
	return visitor.Limiter
}

func Limit(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ip, _, err := net.SplitHostPort(request.RemoteAddr)

		if err != nil {
			fmt.Println(err)
			utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)
			return
		}

		limiter := GetLimiter(utils.SHA512(ip))

		if limiter.Allow() == false {
			utils.JSONResponse(writer, Message{Success: false, Message: http.StatusText(429)}, http.StatusTooManyRequests)
			return
		}

		handler.ServeHTTP(writer, request)
	})
}

func CleanUpVisitors() {
	for {
		time.Sleep(time.Minute)
		visitorsMutex.Lock()

		for hash, visitor := range visitors {
			if time.Since(visitor.LastSeen) > 3*time.Minute {
				delete(visitors, hash)
			}
		}

		visitorsMutex.Unlock()
	}
}
