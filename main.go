package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/faizainur/idp-catena/middlewares"
	"github.com/faizainur/idp-catena/services"
	"github.com/faizainur/idp-catena/utils"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	collections = make(map[string]*mongo.Collection)
	redisClient *redis.Client
)

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	mongoClient, err := setupMongoDb(ctx)

	if err != nil {
		log.Fatal(err.Error(), ": Failed to connect to database")
	}
	defer mongoClient.Disconnect(ctx)

	redisClient = setupRedis()

	r := setupRouter()

	//Start server
	r.Run(":4000")
}

func setupRouter() *gin.Engine {

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		log.Fatal("Failed to generate private key")
	}

	jwtService := services.JWTService{PrivateKey: privKey}

	authMiddleware := middlewares.NewAuthMiddleware(collections["credentials"], &jwtService, redisClient)

	router := gin.Default()

	router.Use(cors.Default())

	v1 := router.Group("/v1")
	{
		v1.GET("/ping", ping)
		v1.POST("/register", authMiddleware.RegisterCredential())
		v1.POST("/auth/login", authMiddleware.Login())
	}

	return router

}

func setupMongoDb(ctx context.Context) (*mongo.Client, error) {

	// Load URI from OS variabel environment
	dbConfig := utils.DbUtils{ConnectionString: "mongodb+srv://admin:devcatenaAdmin2021@dev-catena.yuofs.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"}

	client, err := dbConfig.Connect(ctx)

	if err == nil {

		fmt.Println("Connected to database")

		// Database users
		dbUsers := client.Database("users")
		collections["credentials"] = dbUsers.Collection("credentials")

	}

	return client, err

}

func setupRedis() *redis.Client {

	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	return rdb
}

func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "Server is running",
	})
}
