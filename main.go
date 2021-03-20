package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/faizainur/idp-catena/middlewares"
	"github.com/faizainur/idp-catena/services"
	"github.com/faizainur/idp-catena/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

// TODO: Check if email already Exist

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
	router.Use(CORSMiddleware())
	router.LoadHTMLGlob("templates/*")

	v1 := router.Group("/v1")
	{
		v1.GET("/ping", ping)
		v1.GET("/test", authMiddleware.ValidateToken(true), securedEndpoint)
		v1.POST("/reset", authMiddleware.RequestResetPassword)

		auth := v1.Group("/auth")
		{
			auth.POST("/register", authMiddleware.RegisterCredential)
			auth.POST("/login", authMiddleware.Login)
			auth.POST("/validate_token", authMiddleware.ValidateToken(false))
			auth.POST("/refresh_token", authMiddleware.RefreshToken)
			auth.POST("/update_password", authMiddleware.ValidateToken(true), authMiddleware.UpdatePassword)
			auth.POST("/request_reset", authMiddleware.RequestResetPassword)
			auth.GET("/reset_password", authMiddleware.GetResetPassword)
			auth.POST("/reset_password", authMiddleware.SetResetPassword)
		}
	}

	return router

}

func setupMongoDb(ctx context.Context) (*mongo.Client, error) {

	// Load URI from OS variabel environment
	dbConfig := utils.DbUtils{ConnectionString: os.Getenv("MONGODB_URI")}
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

func securedEndpoint(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "Server is running",
	})
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "localhost:4000")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, PUT")

		// if c.Request.Method == "OPTIONS" {
		// 	c.AbortWithStatus(204)
		// 	return
		// }

		c.Next()
	}
}
