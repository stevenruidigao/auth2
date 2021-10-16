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

	host := ""
	port := 8080

	router := mux.NewRouter()
	apiRouter := router.PathPrefix("/api").Subrouter()
	authRouter := apiRouter.PathPrefix("/auth").Subrouter()
	authRouter.Path("/login").Methods(http.MethodPost).HandlerFunc(Login)
	authRouter.Path("/register").Methods(http.MethodPost).HandlerFunc(Register)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	uri := "mongodb://" + DBHost + ":" + DBPort + "/" + DBName
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
	json.NewDecoder(request.Body).Decode(&credentials)

	user := database.FindUser(&database.User{Username: credentials.Username}, userDatabase)

	if user == nil {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, 503)

	} else if credentials.PasswordHash != user.PasswordHash {
		utils.JSONResponse(writer, Message{Success: false, Message: "That password was incorrect."}, 403)

	} else {
		if time.Since(user.TokenTime) > 24*time.Hour {
			user.Token = uuid.NewString()
			user.TokenTime = time.Now()
			database.UpdateUser(user, userDatabase)
			AddCookie(writer, "token", user.Token, 24*time.Hour)
		}

		utils.JSONResponse(writer, Message{Success: true, Message: "You logged in successfully."}, 200)
	}

	fmt.Println("Login User:", credentials)
	fmt.Println("Result:", user)
}

func Register(writer http.ResponseWriter, request *http.Request) {
	var user database.User
	json.NewDecoder(request.Body).Decode(&user)
	user.ID = uuid.NewString()

	result := database.RegisterUser(&user, userDatabase)
	//	fmt.Println(user, *result, user == *result)

	if result != nil && !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An account with that name already exists."}, 401)

	} else if !result.Success {
		utils.JSONResponse(writer, Message{Success: false, Message: "An error occurred."}, 503)

	} else {
		user.Token = uuid.NewString()
		user.TokenTime = time.Now()
		database.UpdateUser(&user, userDatabase)
		AddCookie(writer, "token", user.Token, 24*time.Hour)
		utils.JSONResponse(writer, Message{Success: true, Message: "Your account was created successfully."}, 200)
	}
}

func Authenticate(request *http.Request) *database.User {
	result := database.FindUser(&database.User{Token: request.Header.Get("Bearer")}, userDatabase)

	if result == nil {
		return nil
	}

	return result
}

func AddCookie(writer http.ResponseWriter, name, value string, ttl time.Duration) {
	expire := time.Now().Add(ttl)

	cookie := http.Cookie{
		Name:    name,
		Value:   value,
		Expires: expire,
	}

	http.SetCookie(writer, &cookie)
}
