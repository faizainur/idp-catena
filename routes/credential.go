package routes

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/faizainur/api-idp-catena/models"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	BasicUser string = "basic"
	BankUser  string = "bank"
)

func RegisterCredential(collection *mongo.Collection) gin.HandlerFunc {
	return func(c *gin.Context) {

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		defer cancel()

		var data models.Credential

		if err := c.ShouldBind(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":  http.StatusBadRequest,
				"error": err.Error(),
			})
		} else {
			/* var message strings.Builder

			message.WriteString("Thank you for registering, ")
			message.WriteString(data.Email) */

			// Hashing password
			unsalted := []byte(data.Password)
			saltedPassword, _ := bcrypt.GenerateFromPassword(unsalted, bcrypt.DefaultCost)

			// Add addtional data
			userUid, _ := uuid.NewV4()
			data.UserUid = userUid.String()
			data.Password = string(saltedPassword)
			data.CreatedAt = time.Now().Format(time.RFC3339)
			data.CredentialType = BasicUser
			data.IsAdmin = false
			data.IsEmailVerified = false

			collection.InsertOne(ctx, data)

			// Omit password from http response
			data.Password = ""

			c.JSON(http.StatusOK, data)
		}

	}
}

func Login(collection *mongo.Collection) gin.HandlerFunc {
	return func(c *gin.Context) {

		filter := bson.D{{"email", c.PostForm("email")}}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		defer cancel()

		var data models.Credential

		errMongo := collection.FindOne(ctx, filter).Decode(&data)

		if errMongo != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":  http.StatusBadRequest,
				"error": errMongo.Error(),
			})
			return
		}

		errBcrypt := bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(c.PostForm("password")))

		if errBcrypt != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":  http.StatusUnauthorized,
				"error": "Wrong password",
			})
			return
		}

		data.Password = ""

		c.JSON(http.StatusOK, gin.H{
			"code":    http.StatusOK,
			"message": "User logged in",
			"data":    data,
		})

	}
}

// TODO : Validate email and password using regex
