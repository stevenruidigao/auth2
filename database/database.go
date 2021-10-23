package database

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func FindUser(user *User, database *mongo.Database) *User {
	var result *User
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var cur *mongo.SingleResult

	if user.Username != "" {
		cur = database.Collection("Users").FindOne(ctx, bson.M{"username": user.Username})

	} else if user.ID != "" {
		cur = database.Collection("Users").FindOne(ctx, bson.M{"id": user.ID})

	} else if user.Token != "" {
		cur = database.Collection("Users").FindOne(ctx, bson.M{"token": user.Token})

	} else {
		return nil
	}

	if cur.Err() == mongo.ErrNoDocuments {
		return nil

	} else if cur.Err() != nil {
		fmt.Println("Err:", cur.Err())
		user.Success = false
		return user
	}

	cur.Decode(&result)
	result.Success = true
	return result
}

func RegisterUser(user *User, database *mongo.Database) *User {
	var result *User
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cur := database.Collection("Users").FindOne(ctx, bson.M{"username": user.Username})

	if cur.Err() == nil {
		cur.Decode(&result)
		result.Success = false
		return result

	} else if cur.Err() != mongo.ErrNoDocuments {
		fmt.Println("Err:", cur.Err())
		return nil
	}

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := database.Collection("Users").InsertOne(ctx, user)

	if err != nil {
		fmt.Println("Err:", err)
		return nil
	}

	user.Success = true
	return user
}

func UpdateUser(user *User, database *mongo.Database) *User {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := database.Collection("Users").UpdateOne(ctx, bson.M{"id": user.ID}, bson.M{"$set": &user})

	if err != nil {
		fmt.Println("Err:", err)
		return nil
	}

	user.Success = true
	return user
}
