package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/faizainur/api-idp-catena/utils"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	collections map[string]*mongo.Collection
)

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	client, err := setupDatabase(ctx)

	if err != nil {
		log.Fatal(err.Error(), ": Failed to connect to database")
	}

	defer client.Disconnect(ctx)

	r := setupRouter()

	//Start server
	r.Run(":3000")
}

func setupRouter() *gin.Engine {

	router := gin.Default()

	v1 := router.Group("/v1")
	{
		v1.GET("/ping", ping)
	}

	return router

}

func setupDatabase(ctx context.Context) (*mongo.Client, error) {

	// Load URI from OS variabel environment
	dbConfig := utils.DbUtils{ConnectionString: os.Getenv("MONGO_URI_DATABASE")}

	client, err := dbConfig.Connect(ctx)

	if err == nil {

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
