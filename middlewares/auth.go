package middlewares

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/faizainur/idp-catena/models"
	"github.com/faizainur/idp-catena/services"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
)

const (
	cookieDuration int = 86400
)

type authMiddleware struct {
	jwtService *services.JWTService
	rdb        *redis.Client

	userManagementService *services.UserManagement
}

func NewAuthMiddleware(j *services.JWTService, u *services.UserManagement, r *redis.Client) *authMiddleware {

	return &authMiddleware{
		jwtService:            j,
		userManagementService: u,
		rdb:                   r,
		// hydraPublic: hydraPublic,
	}
}

func (a *authMiddleware) RegisterCredential(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, err := a.userManagementService.RegisterHandler(ctx, c.PostForm("email"), c.PostForm("password"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, data)
}

func (a *authMiddleware) Login(c *gin.Context) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, errLoginHandler := a.userManagementService.LoginHandler(ctx, c.PostForm("email"), c.PostForm("password"))
	if errLoginHandler != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": errLoginHandler.Error(),
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

	c.SetCookie("refreshToken", refreshToken.String(), cookieDuration, "/v1/auth/refresh_token", "localhost", false, true)
	c.SetCookie("refreshToken", refreshToken.String(), cookieDuration, "/v1/auth/logout", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{
		"code":      http.StatusOK,
		"message":   "User logged in",
		"data":      data,
		"jwt_token": string(jwtToken),
	})
}

func (a *authMiddleware) Logout(c *gin.Context) {

	authHeader := strings.Trim(c.GetHeader("Authorization"), " ")
	authToken := strings.Split(authHeader, " ")[1]

	refreshToken, errCookie := c.Cookie("refreshToken")
	if errCookie != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": "No cookie found",
		})
		return
	}

	email := c.GetString("email")

	status, err := a.invalidateToken(authToken, refreshToken, email)
	if !status {
		log.Fatal("Failed to set key : ", err.Error())
	}
	c.String(http.StatusOK, "%s", "Logged out")
}

func (a *authMiddleware) ValidateToken(mode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.Trim(c.GetHeader("Authorization"), " ")
		if len(authHeader) < 2 {
			if !mode {
				c.JSON(http.StatusUnauthorized, gin.H{
					"code":  http.StatusUnauthorized,
					"error": "No JWT Token provided 1",
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":  http.StatusUnauthorized,
				"error": "No JWT Token provided",
			})
			return
		}

		authToken := strings.Split(authHeader, " ")[1]

		isInvalidated := a.isInvalidatedToken(authToken)
		if isInvalidated {
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

		userUid := payload["userUid"]
		email := payload["sub"]

		if !mode {
			c.JSON(http.StatusOK, gin.H{
				"code":     http.StatusOK,
				"is_valid": true,
				"data": map[string]interface{}{
					"user_uid": userUid,
					"email":    email,
				},
			})
			return
		}

		c.Set("userUid", userUid)
		c.Set("email", email)
		c.Next()
	}
}

func (a *authMiddleware) isInvalidatedToken(token string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hash := a.hashToken(token)

	_, err := a.rdb.Get(ctx, hash).Result()

	if err != redis.Nil {
		return true
	} else if err != nil && err != redis.Nil {
		log.Fatal(err.Error())
	}
	return false
}

func (a *authMiddleware) invalidateToken(jwt string, refreshToken string, email string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hash := a.hashToken(jwt)

	err := a.rdb.Set(ctx, hash, email, 5*time.Minute).Err()
	if err != nil {
		return false, err
	}

	berr := a.rdb.Del(ctx, refreshToken).Err()
	if berr != nil {
		return false, berr
	}
	return true, nil
}

func (a *authMiddleware) hashToken(token string) string {
	hashGen := sha1.New()

	hashGen.Write([]byte(token))
	hash := hashGen.Sum(nil)
	encodedBase64Hash := base64.StdEncoding.EncodeToString(hash)

	return encodedBase64Hash
}

func (a *authMiddleware) RefreshToken(c *gin.Context) {

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
		log.Fatal(err.Error())
	}

	var data models.Credential
	{
		err := json.Unmarshal([]byte(val), &data)
		if err != nil {
			log.Fatal(err.Error())
		}

		if data.RefreshToken != refreshToken && data.UserUid != userUid {
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
			"sub":            email,
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

func (a *authMiddleware) RequestResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := c.PostForm("email")

	isExist, err := a.userManagementService.IsEmailExist(email)
	if err != nil {
		log.Fatal(err.Error())
	}

	if !isExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": "Email is not registered",
		})
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
	link.WriteString("http://ec2-54-204-24-52.compute-1.amazonaws.com/api/v1/auth/reset_password?token=")
	link.WriteString(guid.String())
	link.WriteString("&email=")
	link.WriteString(email)

	c.JSON(200, gin.H{"url_reset": link.String()})
}

func (a *authMiddleware) GetResetPassword(c *gin.Context) {
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
		log.Fatal(err.Error())
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

func (a *authMiddleware) SetResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := c.PostForm("email")
	password := c.PostForm("password")
	token := c.PostForm("token")

	val, errRedis := a.rdb.Get(ctx, email).Result()

	if errRedis == redis.Nil {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	} else if errRedis != nil {
		log.Fatal("err.Error()")
	}

	if val != token {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	}

	err := a.userManagementService.UpdatePasswordHandler(ctx, email, password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": err.Error(),
		})
		return
	}

	_, errRedis2 := a.rdb.Del(ctx, email).Result()

	if errRedis2 == redis.Nil {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
		return
	} else if errRedis2 != nil {
		log.Fatal(err.Error())
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "Password updated",
	})
}

func (a *authMiddleware) UpdatePassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userUid := c.GetString("userUid")
	password := c.PostForm("password")

	err := a.userManagementService.UpdatePasswordHandler(ctx, userUid, password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "Password updated",
	})
}
