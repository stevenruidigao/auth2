package main

import (
	"authenticate/database"
	"authenticate/utils"

	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type Message struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

var userDatabase *mongo.Database

func main() {
	DBHost := "127.0.0.1"
	DBPort := "27017"
	DBName := "authenticate"
	DBMaxPoolSize := "50"

	host := ""
	port := 8080

	router := mux.NewRouter()
	apiRouter := router.PathPrefix("/api").Subrouter()
	authRouter := apiRouter.PathPrefix("/auth").Subrouter()
	authRouter.Path("/login").Methods(http.MethodPost).HandlerFunc(Login)
	authRouter.Path("/register").Methods(http.MethodPost).HandlerFunc(Register)
	authRouter.Path("/salt").Methods(http.MethodPost).HandlerFunc(Salt)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

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

	fmt.Println("Listening on " + host + ":" + strconv.Itoa(port))
	http.ListenAndServe(host+":"+strconv.Itoa(port), router)
}

func Login(writer http.ResponseWriter, request *http.Request) {
	var credentials database.User
	err := json.NewDecoder(request.Body).Decode(&credentials)

	if err != nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, 200)
		return
	}

	user := database.FindUser(&database.User{Username: credentials.Username}, userDatabase)
	credentials.PasswordHash = utils.Argon2(credentials.PasswordHash, user.Salt)

	if user == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, 401)

	} else if !user.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, 500)

	} else if credentials.PasswordHash != user.PasswordHash {
		utils.JSONResponse(writer, Message{Success: false, Message: "That password was incorrect."}, 401)

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

		utils.JSONResponse(writer, Message{Success: true, Message: "You logged in successfully."}, 200)
	}
}

func Register(writer http.ResponseWriter, request *http.Request) {
	var user database.User
	err := json.NewDecoder(request.Body).Decode(&user)

	if err != nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, 500)
		return
	}

	user.ID = uuid.NewString()
	user.PasswordHash = utils.Argon2(user.PasswordHash, user.Salt)
	result := database.RegisterUser(&user, userDatabase)

	if result != nil && !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An account with that name already exists."}, 403)

	} else if !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, 500)

	} else {
		user.Token = uuid.NewString()
		user.TokenExpires = time.Now().Add(24 * time.Hour)
		database.UpdateUser(&user, userDatabase)
		utils.AddCookie(writer, "token", user.Token, time.Until(user.TokenExpires))
		utils.JSONResponse(writer, Message{Success: true, Message: "Your account was created successfully."}, 200)
	}
}

func Salt(writer http.ResponseWriter, request *http.Request) {
	var user database.User
	json.NewDecoder(request.Body).Decode(&user)
	result := database.FindUser(&database.User{Username: user.Username}, userDatabase)

	if result == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "That user couldn't be found."}, 401)

	} else if !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, 500)

	} else {
		utils.JSONResponse(writer, Message{Success: true, Message: result.Salt}, 200)
	}
}

func Authenticate(request *http.Request) *database.User {
	result := database.FindUser(&database.User{Token: request.Header.Get("Bearer")}, userDatabase)

	if result == nil {
		return nil
	}

	return result
}
