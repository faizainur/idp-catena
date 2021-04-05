package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
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

	redisHost      string
	mongoDbUri     string
	hydraAdminHost string
)

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	redisHost = os.Getenv("REDIS_HOST")
	mongoDbUri = os.Getenv("MONGODB_URI")
	hydraAdminHost = os.Getenv("HYDRA_ADMIN_HOST") // example "localhost:9001"

	fmt.Println("Redis Host = ", redisHost)
	fmt.Println("MongoDB URI = ", mongoDbUri)

	mongoClient, err := setupMongoDb(ctx)
	if err != nil {
		log.Fatal(err.Error(), ": Failed to connect to database")
	}
	defer mongoClient.Disconnect(ctx)

	redisClient = setupRedis()

	r := setupRouter()

	//Start server
	var port string
	if os.Getenv("PORT_LISTEN") != "" {
		port = fmt.Sprintf(":%s", os.Getenv("PORT_LISTEN"))
	}
	r.Run(port)
}

func setupRouter() *gin.Engine {

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate private key")
	}

	jwtService := services.JWTService{PrivateKey: privKey}
	userManagementService := services.UserManagement{Collection: collections["credentials"]}

	authMiddleware := middlewares.NewAuthMiddleware(&jwtService, &userManagementService, redisClient)
	oauth2Middleware := middlewares.NewOauth2Middleware(&userManagementService, hydraAdminHost)

	router := gin.Default()
	router.Use(CORSMiddleware())
	router.LoadHTMLGlob("templates/*")

	v1 := router.Group("/api/v1")
	{
		v1.GET("/ping", ping)
		v1.GET("/test", authMiddleware.ValidateToken(true), securedEndpoint)

		auth := v1.Group("/auth")
		{
			auth.POST("/register", authMiddleware.RegisterCredential)
			auth.POST("/login", authMiddleware.Login)
			auth.POST("/logout", authMiddleware.ValidateToken(true), authMiddleware.Logout)
			auth.POST("/validate_token", authMiddleware.ValidateToken(false))
			auth.POST("/refresh_token", authMiddleware.RefreshToken)
			auth.POST("/update_password", authMiddleware.ValidateToken(true), authMiddleware.UpdatePassword)
			auth.POST("/request_reset", authMiddleware.RequestResetPassword)
			auth.GET("/reset_password", authMiddleware.GetResetPassword)
			auth.POST("/reset_password", authMiddleware.SetResetPassword)
		}

		oauth2 := v1.Group("/oauth2/")
		{
			oauth2.GET("/login", oauth2Middleware.RequestOauthLogin)
			oauth2.POST("/login", oauth2Middleware.OauthLogin)
			oauth2.GET("/authorize", oauth2Middleware.RequestOauthConsent)
			oauth2.POST("/authorize", oauth2Middleware.OauthConsent)
			oauth2.POST("/client/create", oauth2Middleware.CreateOauthClient)
		}
	}

	return router

}

func setupMongoDb(ctx context.Context) (*mongo.Client, error) {

	// Load URI from OS variabel environment
	dbConfig := utils.DbUtils{ConnectionString: mongoDbUri}
	client, err := dbConfig.Connect(ctx)

	if err == nil {
		fmt.Println("Connected to Mongo URI")

		// Connect Database
		dbUsers := client.Database("users")
		dbOauth2 := client.Database("oauth2")

		// Get Collections
		collections["credentials"] = dbUsers.Collection("credentials")
		collections["oauth2_client_apps"] = dbOauth2.Collection("client_apps")
	}
	return client, err
}

func setupRedis() *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisHost,
		Password: "",
		DB:       0,
	})

	return rdb
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
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
