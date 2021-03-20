package middlewares

import (
	"context"
	"encoding/json"
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
	"go.mongodb.org/mongo-driver/mongo/options"
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

func (a *AuthMiddleware) RegisterCredential(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var data models.Credential

	email := c.PostForm("email")
	password := c.PostForm("password")

	// Validate email and password
	if isValidEmail := validator.IsValidEmail(email); !isValidEmail {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": "Invalid email address",
		})
		return
	}

	isEmailExist, err := a.isEmailExist(email)
	if err != nil {
		log.Fatal(err.Error())
	}

	if isEmailExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": "Email already exist",
		})
		return
	}

	// Hashing password
	unsalted := []byte(password)
	saltedPassword, _ := bcrypt.GenerateFromPassword(unsalted, bcrypt.DefaultCost)

	// Add addtional data
	userUid, _ := uuid.NewV4()
	data.UserUid = userUid.String()
	data.Email = email
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

func (a *AuthMiddleware) Login(c *gin.Context) {
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

func (a *AuthMiddleware) ValidateToken(mode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.Trim(c.GetHeader("Authorization"), " ")
		authToken := strings.Split(authHeader, " ")[1]

		isValid, payload := a.jwtService.ValidateToken([]byte(authToken))

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
				"code":     http.StatusOK,
				"is_valid": true,
				"data": map[string]interface{}{
					"user_uid": payload["userUid"],
					"email":    payload["email"],
				},
			})
			return
		}
		c.Set("userUid", payload["userUid"])
		c.Set("email", payload["email"])
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

	// fmt.Println(val, userUid, email)

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

func (a *AuthMiddleware) isEmailExist(email string) (bool, error) {
	var isExist bool = false

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Count().SetMaxTime(2 * time.Second)
	count, err := a.collection.CountDocuments(ctx, bson.D{{"email", email}}, opts)

	if count > 0 && err == nil {
		isExist = true
	}

	return isExist, err
}

func (a *AuthMiddleware) UpdatePassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userUid := c.GetString("userUid")

	unsalted := []byte(c.PostForm("password"))
	saltedPassword, _ := bcrypt.GenerateFromPassword(unsalted, bcrypt.DefaultCost)

	var updatedDocument bson.M
	err := a.collection.FindOneAndUpdate(
		ctx,
		bson.D{{"user_uid", userUid}},
		bson.D{{"$set", bson.D{{"password", string(saltedPassword)}}}},
		options.FindOneAndUpdate().SetMaxTime(2*time.Second),
		options.FindOneAndUpdate().SetUpsert(false),
	).Decode(&updatedDocument)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.String(http.StatusBadRequest, "%s", "Bad request")
		}
		log.Fatal(err.Error())
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "Password updated",
	})
}

func (a *AuthMiddleware) RequestResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := c.PostForm("email")

	isExist, err := a.isEmailExist(email)
	if err != nil {
		log.Fatal(err.Error())
	}

	if !isExist {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	}

	guid, err := uuid.NewV4()
	// calc := sha256.New()
	// token := calc.Sum([]byte(guid.String()))

	errRedis := a.rdb.Set(ctx, email, guid.String(), 5*time.Minute).Err()
	if errRedis != nil {
		log.Fatal("Failed to set key : ", err.Error())
	}

	// Generate reset link page
	var link strings.Builder
	link.WriteString("localhost:4000/v1/auth/reset_password?token=")
	link.WriteString(guid.String())
	link.WriteString("&email=")
	link.WriteString(email)

	c.JSON(200, gin.H{"url_reset": link.String()})
}

func (a *AuthMiddleware) GetResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token := c.Query("token")
	email := c.Query("email")

	if token == "" || email == "" {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	}

	val, err := a.rdb.Get(ctx, email).Result()

	if err == redis.Nil {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	} else if err != nil {
		log.Fatal("err.Error()")
	}

	if val != token {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	}

	c.HTML(http.StatusOK, "reset_password.tmpl", gin.H{
		"url":   "reset_password",
		"token": token,
		"email": email,
	})
}

func (a *AuthMiddleware) SetResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := c.PostForm("email")
	password := c.PostForm("password")
	token := c.PostForm("token")

	val, err := a.rdb.Get(ctx, email).Result()

	if err == redis.Nil {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	} else if err != nil {
		log.Fatal("err.Error()")
	}

	if val != token {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	}

	unsalted := []byte(password)
	saltedPassword, _ := bcrypt.GenerateFromPassword(unsalted, bcrypt.DefaultCost)

	var updatedDocument bson.M
	errMongo := a.collection.FindOneAndUpdate(
		ctx,
		bson.D{{"email", email}},
		bson.D{{"$set", bson.D{{"password", string(saltedPassword)}}}},
		options.FindOneAndUpdate().SetMaxTime(2*time.Second),
		options.FindOneAndUpdate().SetUpsert(false),
	).Decode(&updatedDocument)

	if errMongo != nil {
		if err == mongo.ErrNoDocuments {
			c.String(http.StatusBadRequest, "%s", "Bad Request")
		}
		log.Fatal(err.Error())
	}

	_, errRedis2 := a.rdb.Del(ctx, email).Result()

	if errRedis2 == redis.Nil {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	} else if errRedis2 != nil {
		log.Fatal("err.Error()")
	}

	c.String(http.StatusOK, "%s", "Password Updated")

}
