package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"authenticate/database"
	"authenticate/session"
	"authenticate/utils"
)

type Message struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
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
	//	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter := mux.NewRouter().PathPrefix("/api").Subrouter()
	authRouter := apiRouter.PathPrefix("/auth").Subrouter()
	authRouter.Path("/login").Methods(http.MethodPost).HandlerFunc(Login)
	authRouter.Path("/register").Methods(http.MethodPost).HandlerFunc(Register)
	authRouter.Path("/register/webauthn/begin").Methods(http.MethodPost).HandlerFunc(BeginWebauthnRegistration)
	authRouter.Path("/salt").Methods(http.MethodPost).HandlerFunc(Salt)
	router.PathPrefix("/api").Handler(Limit(apiRouter))
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
	var credentials database.User
	err := json.NewDecoder(request.Body).Decode(&credentials)

	if err != nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusOK)
		return
	}

	user := database.FindUser(&database.User{Username: credentials.Username}, userDatabase)

	if user == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, http.StatusUnauthorized)

	} else if !user.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, http.StatusInternalServerError)

	} else {
		credentials.PasswordHash = utils.Argon2(credentials.PasswordHash, user.Salt)

		if credentials.PasswordHash != user.PasswordHash {
			utils.JSONResponse(writer, Message{Success: false, Message: "That password was incorrect."}, http.StatusUnauthorized)

		} else {
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
		}
	}
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
	result := database.FindUser(&database.User{Token: request.Header.Get("Bearer")}, userDatabase)

	if result == nil {
		return nil
	}

	return result
}

func BeginWebauthnRegistration(writer http.ResponseWriter, request *http.Request) {
	var user database.User
	json.NewDecoder(request.Body).Decode(&user)
	result := database.FindUser(&database.User{Username: user.Username}, userDatabase)

	if result == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, http.StatusInternalServerError)
		return
	}

	options, sessionData, err := webAuthn.BeginRegistration(result)

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
