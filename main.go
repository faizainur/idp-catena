package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/faizainur/api-idp-catena/utils"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	collections = make(map[string]*mongo.Collection)
)

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	client, err := setupDatabase(ctx)

	defer client.Disconnect(ctx)

	if err != nil {
		log.Fatal(err.Error(), ": Failed to connect to database")
	}

	r := setupRouter()

	//Start server
	r.Run(":4000")
}

func setupRouter() *gin.Engine {

	router := gin.Default()

	v1 := router.Group("/v1")
	{
		v1.GET("/ping", ping)
		v1.POST("/register", routes.RegisterCredential(collections["credentials"]))
		v1.POST("/auth/login", routes.Login(collections["credentials"]))
	}

	return router

}

func setupDatabase(ctx context.Context) (*mongo.Client, error) {

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

func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "Server is running",
	})
}
