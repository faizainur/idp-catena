package middlewares

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/faizainur/idp-catena/models"
	"github.com/faizainur/idp-catena/services"
	"github.com/faizainur/idp-catena/validator"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	BasicUser string = "basic"
	BankUser  string = "bank"

	cookieDuration int = 86400
)

type AuthMiddleware struct {
	collection *mongo.Collection
	jwtService *services.JWTService
	rdb        *redis.Client
}

func NewAuthMiddleware(c *mongo.Collection, j *services.JWTService, r *redis.Client) *AuthMiddleware {
	return &AuthMiddleware{
		collection: c,
		jwtService: j,
		rdb:        r,
	}
}

func (a *AuthMiddleware) RegisterCredential() gin.HandlerFunc {
	return func(c *gin.Context) {

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		defer cancel()

		var data models.Credential

		if err := c.ShouldBind(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":  http.StatusBadRequest,
				"error": err.Error(),
			})
			return
		}

		// Validate email and password
		if isValidEmail := validator.IsValidEmail(data.Email); !isValidEmail {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":  http.StatusBadRequest,
				"error": "Invalid email address",
			})
			return
		}

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

		a.collection.InsertOne(ctx, data)

		// Omit password from http response
		data.Password = ""

		c.JSON(http.StatusOK, data)

	}
}

func (a *AuthMiddleware) Login() gin.HandlerFunc {
	return func(c *gin.Context) {

		filter := bson.D{{"email", c.PostForm("email")}}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var data models.Credential

		errMongo := a.collection.FindOne(ctx, filter).Decode(&data)
		if errMongo != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":  http.StatusBadRequest,
				"error": "Email is not registered",
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

		var claims = map[string]interface{}{
			"userUid":        data.UserUid,
			"sub":            data.Email,
			"credentialType": data.CredentialType,
			"isAdmin":        data.IsAdmin,
			"iss":            "Caneta IDP Server",
			"iat":            time.Now().Unix(),
			"exp":            time.Now().Add(10 * time.Minute).Unix(),
		}

		jwtToken, _ := a.jwtService.GenerateToken(claims)

		// Generate random refersh token
		refreshToken, _ := uuid.NewV4()

		dataBinary, errJson := json.Marshal(map[string]interface{}{
			"user_uid":        data.UserUid,
			"email":           data.Email,
			"credential_type": data.CredentialType,
			"is_admin":        data.IsAdmin,
		})

		if errJson != nil {
			log.Fatal(errJson.Error())
		}

		err := a.rdb.Set(ctx, refreshToken.String(), dataBinary, 24*time.Hour).Err()
		if err != nil {
			log.Fatal("Failed to set key : ", err.Error())
		}

		c.SetCookie("refreshToken", refreshToken.String(), cookieDuration, "/v1/auth/refresh", "localhost", false, true)
		c.JSON(http.StatusOK, gin.H{
			"code":      http.StatusOK,
			"message":   "User logged in",
			"data":      data,
			"jwt_token": string(jwtToken),
		})

	}
}

func (a *AuthMiddleware) ValidateToken(mode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.Trim(c.GetHeader("Authorization"), " ")
		authToken := strings.Split(authHeader, " ")[1]

		isValid := a.jwtService.ValidateToken([]byte(authToken))

		if !isValid {
			if !mode {
				c.JSON(http.StatusUnauthorized, gin.H{
					"code":     http.StatusUnauthorized,
					"is_valid": false,
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":     http.StatusUnauthorized,
				"is_valid": false,
			})
			return
		}

		if !mode {
			c.JSON(http.StatusOK, gin.H{
				"code":     http.StatusUnauthorized,
				"is_valid": true,
			})
			return
		}
		c.Next()
	}
}

func (a *AuthMiddleware) RefreshToken(c *gin.Context) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	refreshToken, errCookie := c.Cookie("refreshToken")
	if errCookie != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": "No cookie found",
		})
		return
	}

	userUid := c.PostForm("user_uid")
	email := c.PostForm("email")

	val, err := a.rdb.Get(ctx, refreshToken).Result()

	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":         http.StatusUnauthorized,
			"error":        "Please login again",
			"need_relogin": true,
		})
		return
	} else if err != nil {
		log.Fatal("err.Error()")
	}

	fmt.Println(val, userUid, email)

	// data := models.Credential{}
	var data models.Credential
	{
		err := json.Unmarshal([]byte(val), &data)
		if err != nil {
			log.Fatal(err.Error())
		}

		if data.Email != email && data.UserUid != userUid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":         http.StatusUnauthorized,
				"error":        "Wrong email and user uid",
				"need_relogin": true,
				"data":         data,
			})
			return
		}

		var claims = map[string]interface{}{
			"userUid":        data.UserUid,
			"sub":            data.Email,
			"credentialType": data.CredentialType,
			"isAdmin":        data.IsAdmin,
			"iss":            "Caneta IDP Server",
			"iat":            time.Now().Unix(),
			"exp":            time.Now().Add(5 * time.Minute).Unix(),
		}

		jwtToken, _ := a.jwtService.GenerateToken(claims)

		c.JSON(http.StatusOK, gin.H{
			"code":        http.StatusOK,
			"needRelogin": false,
			"jwt_token":   string(jwtToken),
		})
		return
	}

}
