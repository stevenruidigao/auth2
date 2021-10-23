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
		RPID:          "authenticate.ands.ee",
		RPOrigin:      "https://authenticate.ands.ee",
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
	//fmt.Println(user)
	result := database.FindUser(&database.User{Username: user.Username}, userDatabase)

	if result == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, http.StatusUnauthorized)

	} else if !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)

	} else {
		fmt.Println(result, result.Success)
		utils.JSONResponse(writer, Message{Success: true, Message: result.Salt}, http.StatusOK)
	}
}

func Authenticate(request *http.Request) (*database.User, *database.Token) {
	auth, err := request.Cookie("token")

	if err != nil {
		fmt.Println(err)
		return nil, nil
	}

	fmt.Println(auth.Value)
	user := database.FindUser(&database.User{Token: auth.Value}, userDatabase)
	// result := database.FindUser(&database.User{Token: request.Header.Get("Bearer")}, userDatabase)

	if user == nil {
		return nil, nil
	}

	var token *database.Token

	for _, token := range user.Tokens {
		/*if token == nil || time.Since(token.TokenExpires) > 0 {
		user.Token = uuid.NewString()
		user.TokenExpires = time.Now().Add(24 * time.Hour)
		user.Tokens = append(user.Tokens, database.Token{TokenHash: utils.SHA512(user.Token), TokenExpires: user.TokenExpires})
		database.UpdateUser(user, userDatabase)
		utils.AddCookie(writer, "token", user.Token, time.Until(user.TokenExpires))
		*/

		if token.TokenHash == utils.SHA512(auth.Value) {
			break
		}
	}

	return user, token
}

func RegisterTOTP(writer http.ResponseWriter, request *http.Request) {
	user, _ := Authenticate(request)

	if user == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "You need to log in first."}, http.StatusUnauthorized)
		return
	}

	if user.TOTPSecret != "" {
		utils.JSONResponse(writer, Message{Success: false, Message: "You already have TOTP enabled."}, http.StatusUnauthorized)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Authenticate.ands.ee", AccountName: user.Username})

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

	utils.JSONResponse(writer, Message{Success: true, Message: "Your TOTP key was generated.", Data: key.URL()}, http.StatusOK)
	fmt.Println(key, key.Secret(), image)
	user.Enabled.TOTP = true
	user.Required = 2
	user.TOTPSecret = key.Secret()
	database.UpdateUser(user, userDatabase)
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
