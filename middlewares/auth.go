package middlewares

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/faizainur/idp-catena/models"
	"github.com/faizainur/idp-catena/services"
	"github.com/faizainur/idp-catena/validator"
	"github.com/gin-gonic/gin"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	hydraModels "github.com/ory/hydra-client-go/models"
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
	hydraAdmin admin.ClientService
	// hydraPublic *client.OryHydra
}

func NewAuthMiddleware(c *mongo.Collection, j *services.JWTService, r *redis.Client) *AuthMiddleware {

	// adminUrl, _ := url.Parse("http://localhost:9001")
	// hydraAdmin := client.NewHTTPClientWithConfig(nil, &client.TransportConfig{
	// 	Schemes:  []string{adminUrl.Scheme},
	// 	Host:     adminUrl.Host,
	// 	BasePath: adminUrl.Path,
	// })

	// publicUrl, _ := url.Parse("http://localhost:9000/")
	// hydraPublic := client.NewHTTPClientWithConfig(nil, &client.TransportConfig{
	// 	Schemes:  []string{publicUrl.Scheme},
	// 	Host:     publicUrl.Host,
	// 	BasePath: publicUrl.Path,
	// })

	skipTlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 0,
	}
	transport := httptransport.NewWithClient("localhost:9001", "/", []string{"https"}, skipTlsClient)
	hydra := client.New(transport, nil)

	return &AuthMiddleware{
		collection: c,
		jwtService: j,
		rdb:        r,
		hydraAdmin: hydra.Admin,
		// hydraPublic: hydraPublic,
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

func (a *AuthMiddleware) loginHandler(ctx context.Context, email string, password string) (bool, models.Credential, string) {
	var data models.Credential

	filter := bson.D{{"email", email}}

	errMongo := a.collection.FindOne(ctx, filter).Decode(&data)
	if errMongo != nil {
		return false, models.Credential{}, "Email is not registered"
	}

	errBcrypt := bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(password))
	if errBcrypt != nil {
		return false, models.Credential{}, "Wrong password"
	}
	return true, data, ""
}

func (a *AuthMiddleware) Login(c *gin.Context) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	checkLogin, data, errLogin := a.loginHandler(ctx, c.PostForm("email"), c.PostForm("password"))
	if !checkLogin {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  http.StatusBadRequest,
			"error": errLogin,
		})
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

// func GetLoginRequest(loginChallenge string)  {
// 	var link strings.Builder
// 	link.WriteString("http://localhost:9001/oauth2/auth/requests/login?login_challenge=")
// 	link.WriteString(loginChallenge)

// 	headers := map[string][]string{
//         "Accept": []string{"application/json"},
//     }
// }

func (a *AuthMiddleware) RequestOauthLogin(c *gin.Context) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	challange := strings.TrimSpace(c.Query("login_challenge"))
	fmt.Println(challange)
	fmt.Println("Hello")

	params := admin.NewGetLoginRequestParams()
	params.WithContext(ctx)
	params.SetLoginChallenge(challange)

	responseGetLoginRequest, err := a.hydraAdmin.GetLoginRequest(params)
	if err != nil {
		switch e := err.(type) {
		case (*admin.GetLoginRequestConflict):
			fmt.Println("A")
		case (*admin.GetLoginRequestBadRequest):
			fmt.Println("B")
		case (*admin.GetLoginRequestNotFound):
			fmt.Println("C")
		case (*admin.GetLoginRequestInternalServerError):
			fmt.Println("D")
		default:
			fmt.Println("Default", e)
		}
		c.String(http.StatusBadRequest, "%s", "Failed getting login request from ory hydra", err.Error())
		log.Printf("verbose error info: %#v", err)

		return
	}

	skip := false
	if responseGetLoginRequest.GetPayload().Skip != nil {
		skip = *responseGetLoginRequest.GetPayload().Skip
	}

	if skip {
		loginAcceptParams := admin.NewAcceptLoginRequestParams()
		loginAcceptParams.WithContext(ctx)
		loginAcceptParams.SetLoginChallenge(challange)
		loginAcceptParams.SetBody(&hydraModels.AcceptLoginRequest{
			Subject: responseGetLoginRequest.GetPayload().Subject,
		})

		responseLoginAccept, err := a.hydraAdmin.AcceptLoginRequest(loginAcceptParams)
		if err != nil {
			c.String(http.StatusBadGateway, "%s", "Cannot accept login request")
			return
		}

		c.Redirect(http.StatusFound, *responseLoginAccept.GetPayload().RedirectTo)
		return
	}

	c.HTML(http.StatusOK, "oauth2_login.tmpl", gin.H{
		"checkEmailPassword": false,
		"url":                "http://localhost:8000/v1/oauth2/login",
	})
}

func (a *AuthMiddleware) OauthLogin(c *gin.Context) {
	challange := c.PostForm("login_challenge")
	email := c.PostForm("email")
	password := c.PostForm("password")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	checkLogin, data, _ := a.loginHandler(ctx, email, password)

	if !checkLogin {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "login failed",
		})
		return
	}

	loginAcceptParams := admin.NewAcceptLoginRequestParams()
	loginAcceptParams.WithContext(ctx)
	loginAcceptParams.SetLoginChallenge(challange)
	loginAcceptParams.SetBody(&hydraModels.AcceptLoginRequest{
		Subject:     &email,
		Remember:    true,
		RememberFor: 3600,
	})

	acceptLoginResponse, err := a.hydraAdmin.AcceptLoginRequest(loginAcceptParams)
	if err != nil {
		// if error, redirects to ...
		str := fmt.Sprint("error AcceptLoginRequest", err.Error())
		c.String(http.StatusUnprocessableEntity, str)
	}

	data.Password = ""
	c.JSON(http.StatusOK, gin.H{
		"url_redirect": *acceptLoginResponse.GetPayload().RedirectTo,
	})

	// c.JSON(http.StatusOK, gin.H{
	// 	"url_redirect": "https://www.microsoft.com",
	// })
	fmt.Println("login challange: ", challange)
	// c.JSON(http.StatusOK, data)
}

func (a *AuthMiddleware) Logout(c *gin.Context) {

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
	fmt.Println(email)

	status, err := a.invalidateToken(authToken, refreshToken, email)
	if !status {
		log.Fatal("Failed to set key : ", err.Error())
	}
	c.String(http.StatusOK, "%s", "Logged out")
}

func (a *AuthMiddleware) RequestOauthConsent(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	consentChallange := c.Query("consent_challenge")
	if consentChallange == "" {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
	}

	consentGetParams := admin.NewGetConsentRequestParams()
	consentGetParams.WithContext(ctx)
	consentGetParams.SetConsentChallenge(consentChallange)

	consentGetResponse, err := a.hydraAdmin.GetConsentRequest(consentGetParams)
	if err != nil {
		c.String(http.StatusBadRequest, "%s", "Failed getting params request from ory hydra")
		return
	}

	if consentGetResponse.GetPayload().Skip {
		consentAcceptBody := &hydraModels.AcceptConsentRequest{
			GrantAccessTokenAudience: consentGetResponse.GetPayload().RequestedAccessTokenAudience,
			GrantScope:               consentGetResponse.GetPayload().RequestedScope,
		}

		consentAcceptParams := admin.NewAcceptConsentRequestParams()
		consentAcceptParams.WithConsentChallenge(consentChallange)
		consentAcceptParams.WithContext(ctx)
		consentAcceptParams.WithBody(consentAcceptBody)

		consentAcceptResponse, err := a.hydraAdmin.AcceptConsentRequest(consentAcceptParams)
		if err != nil {
			str := fmt.Sprint("error AcceptConsentRequest", err.Error())
			c.String(http.StatusUnprocessableEntity, "%s", str)
		}

		c.Redirect(http.StatusFound, *consentAcceptResponse.GetPayload().RedirectTo)

	}
	c.HTML(http.StatusOK, "consent_page.tmpl", gin.H{
		"url":         "http://localhost:8000/v1/oauth2/authorize",
		"client_name": consentGetResponse.GetPayload().Client.ClientName,
		"subject":     consentGetResponse.GetPayload().Subject,
	})
}

func (a *AuthMiddleware) OauthConsent(c *gin.Context) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	consentChallange := c.PostForm("consent_challenge")
	isGranted, _ := strconv.ParseBool(c.PostForm("scope_granted"))
	subject := c.PostForm("subject")
	client_name := c.PostForm("client_name")

	fmt.Println(consentChallange, isGranted, subject, client_name)

	consentGetParams := admin.NewGetConsentRequestParams()
	consentGetParams.WithContext(ctx)
	consentGetParams.SetConsentChallenge(consentChallange)

	consentGetResponse, err := a.hydraAdmin.GetConsentRequest(consentGetParams)
	if err != nil {
		// if error, redirects to ...
		str := fmt.Sprint("error GetConsentRequest", err.Error())
		c.String(http.StatusUnprocessableEntity, str)
	}

	if !isGranted {
		consentRejectParams := admin.NewRejectConsentRequestParams()
		consentRejectParams.SetContext(ctx)
		consentRejectParams.SetConsentChallenge(consentChallange)

		consentRejectResponse, _ := a.hydraAdmin.RejectConsentRequest(consentRejectParams)
		if err != nil {
			str := fmt.Sprint("error RejectConsentRequest", err.Error())
			c.String(http.StatusUnprocessableEntity, str)
		}
		// c.JSON(http.StatusOK, gin.H{
		// 	"url_redirect": "https://www.microsoft.com",
		// })
		c.JSON(http.StatusOK, gin.H{
			"url_redirect": consentRejectResponse.GetPayload().RedirectTo,
		})
		return
	}

	consentAcceptBody := &hydraModels.AcceptConsentRequest{
		GrantAccessTokenAudience: consentGetResponse.GetPayload().RequestedAccessTokenAudience,
		GrantScope:               consentGetResponse.GetPayload().RequestedScope,
	}

	consentAcceptParams := admin.NewAcceptConsentRequestParams()
	consentAcceptParams.WithContext(ctx)
	consentAcceptParams.WithConsentChallenge(consentChallange)
	consentAcceptParams.WithBody(consentAcceptBody)

	consentAcceptResponse, err := a.hydraAdmin.AcceptConsentRequest(consentAcceptParams)
	if err != nil {
		str := fmt.Sprint("error AcceptConsentRequest", err.Error())
		c.String(http.StatusUnprocessableEntity, str)
	}
	c.JSON(http.StatusOK, gin.H{
		"url_redirect": consentAcceptResponse.GetPayload().RedirectTo,
	})

	// c.JSON(http.StatusOK, gin.H{
	// 	"url_redirect": "https://www.google.com",
	// })

	// if !isGranted {
	// 	c.JSON(http.StatusOK, gin.H{
	// 		"url_redirect": "https://www.microsoft.com",
	// 	})
	// 	return
	// }
	// c.JSON(http.StatusOK, gin.H{
	// 	"url_redirect": "https://www.google.com",
	// })
}

func (a *AuthMiddleware) ValidateToken(mode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.Trim(c.GetHeader("Authorization"), " ")
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
					"halo":     "halo",
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":     http.StatusUnauthorized,
				"halo":     "halo",
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

func (a *AuthMiddleware) isInvalidatedToken(token string) bool {
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

func (a *AuthMiddleware) invalidateToken(jwt string, refreshToken string, email string) (bool, error) {
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

func (a *AuthMiddleware) hashToken(token string) string {
	hashGen := sha1.New()

	hashGen.Write([]byte(token))
	hash := hashGen.Sum(nil)
	encodedBase64Hash := base64.StdEncoding.EncodeToString(hash)

	return encodedBase64Hash
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
		log.Fatal(err.Error())
	}

	// fmt.Println(val, userUid, email)

	// data := models.Credential{}
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
			return
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
