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
	data, err := bson.Marshal(&user)

	if err != nil {
		fmt.Println(err)
		return nil
	}

	cur := database.Collection("Users").FindOne(ctx, data)

	if cur.Err() != nil {
		fmt.Println(cur.Err())
		return nil
	}

	cur.Decode(&result)
	fmt.Println("Found:", result)

	return result
}

func RegisterUser(user *User, database *mongo.Database) *User {
	var result *User
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cur := database.Collection("Users").FindOne(ctx, bson.M{"username": user.Username})

	if cur.Err() == nil || cur.Err() != mongo.ErrNoDocuments {
		cur.Decode(&result)
		result.Success = false
		fmt.Println("Existing:", result)
		return result
	}

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := database.Collection("Users").InsertOne(ctx, user)

	if err != nil {
		fmt.Println("Err:", err)
		return nil
	}

	fmt.Println("Success:", user)
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

	fmt.Println("Success:", user)
	user.Success = true
	return user
}
