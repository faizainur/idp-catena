package middlewares

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/faizainur/idp-catena/services"
	"github.com/gin-gonic/gin"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/gofrs/uuid"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	hydraModels "github.com/ory/hydra-client-go/models"
)

type oauth2Middleware struct {
	hydraAdmin admin.ClientService
	// hydraPublic *client.OryHydra

	userManagementService *services.UserManagement
}

func NewOauth2Middleware(u *services.UserManagement, hydraAdminHost string) *oauth2Middleware {
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
		Timeout: 10 * time.Second,
	}
	transport := httptransport.NewWithClient(hydraAdminHost, "/", []string{"https"}, skipTlsClient)
	hydra := client.New(transport, nil)

	return &oauth2Middleware{
		hydraAdmin:            hydra.Admin,
		userManagementService: u,
	}
}

func (o *oauth2Middleware) RequestOauthLogin(c *gin.Context) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	challange := strings.TrimSpace(c.Query("login_challenge"))
	fmt.Println(challange)
	fmt.Println("Hello")

	params := admin.NewGetLoginRequestParams()
	params.WithContext(ctx)
	params.SetLoginChallenge(challange)

	responseGetLoginRequest, err := o.hydraAdmin.GetLoginRequest(params)
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

		responseLoginAccept, err := o.hydraAdmin.AcceptLoginRequest(loginAcceptParams)
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

func (o *oauth2Middleware) OauthLogin(c *gin.Context) {
	challange := c.PostForm("login_challenge")
	email := c.PostForm("email")
	password := c.PostForm("password")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, err := o.userManagementService.LoginHandler(ctx, email, password)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":   http.StatusUnauthorized,
			"status": "login failed",
		})
		fmt.Println(err.Error())
		return
	}

	loginAcceptParams := admin.NewAcceptLoginRequestParams()
	loginAcceptParams.WithContext(ctx)
	loginAcceptParams.SetLoginChallenge(challange)
	loginAcceptParams.SetBody(&hydraModels.AcceptLoginRequest{
		Subject:  &email,
		Remember: false,
		// RememberFor: 3600,
	})

	acceptLoginResponse, err := o.hydraAdmin.AcceptLoginRequest(loginAcceptParams)
	if err != nil {
		// if error, redirects to ...
		str := fmt.Sprint("error AcceptLoginRequest", err.Error())
		c.String(http.StatusUnprocessableEntity, str)
	}

	data.Password = ""
	c.JSON(http.StatusOK, gin.H{
		"url_redirect": *acceptLoginResponse.GetPayload().RedirectTo,
	})

	fmt.Println("login challange: ", challange)
}
func (o *oauth2Middleware) RequestOauthConsent(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	consentChallange := c.Query("consent_challenge")
	if consentChallange == "" {
		c.String(http.StatusBadRequest, "%s", "Bad Request")
	}

	consentGetParams := admin.NewGetConsentRequestParams()
	consentGetParams.WithContext(ctx)
	consentGetParams.SetConsentChallenge(consentChallange)

	consentGetResponse, err := o.hydraAdmin.GetConsentRequest(consentGetParams)
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

		consentAcceptResponse, err := o.hydraAdmin.AcceptConsentRequest(consentAcceptParams)
		if err != nil {
			str := fmt.Sprint("error AcceptConsentRequest", err.Error())
			c.String(http.StatusUnprocessableEntity, "%s", str)
		}

		c.Redirect(http.StatusFound, *consentAcceptResponse.GetPayload().RedirectTo)

	}
	fmt.Println(consentGetResponse.GetPayload().Client.ClientName)
	c.HTML(http.StatusOK, "consent_page.tmpl", gin.H{
		"url":         "http://localhost:8000/v1/oauth2/authorize",
		"client_name": consentGetResponse.GetPayload().Client.ClientName,
		"subject":     consentGetResponse.GetPayload().Subject,
	})
}

func (o *oauth2Middleware) OauthConsent(c *gin.Context) {

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

	consentGetResponse, err := o.hydraAdmin.GetConsentRequest(consentGetParams)
	if err != nil {
		// if error, redirects to ...
		str := fmt.Sprint("error GetConsentRequest", err.Error())
		c.String(http.StatusUnprocessableEntity, str)
	}

	if !isGranted {
		consentRejectParams := admin.NewRejectConsentRequestParams()
		consentRejectParams.WithContext(ctx)
		consentRejectParams.SetConsentChallenge(consentChallange)
		consentRejectParams.SetBody(&hydraModels.RejectRequest{
			Error:            "access_denied",
			ErrorDescription: "The resource owner denied the request",
		})

		consentRejectResponse, errRejectConsent := o.hydraAdmin.RejectConsentRequest(consentRejectParams)
		if errRejectConsent != nil {
			str := fmt.Sprint("error RejectConsentRequest", errRejectConsent.Error())
			c.String(http.StatusUnprocessableEntity, str)
			fmt.Println(errRejectConsent.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"url_redirect": consentRejectResponse.GetPayload().RedirectTo,
		})
		fmt.Println("Not allowed")
		return
	}

	consentAcceptBody := &hydraModels.AcceptConsentRequest{
		GrantAccessTokenAudience: consentGetResponse.GetPayload().RequestedAccessTokenAudience,
		GrantScope:               consentGetResponse.GetPayload().RequestedScope,
		Remember:                 true,
		RememberFor:              0,
	}

	consentAcceptParams := admin.NewAcceptConsentRequestParams()
	consentAcceptParams.WithContext(ctx)
	consentAcceptParams.WithConsentChallenge(consentChallange)
	consentAcceptParams.WithBody(consentAcceptBody)

	consentAcceptResponse, err := o.hydraAdmin.AcceptConsentRequest(consentAcceptParams)
	if err != nil {
		str := fmt.Sprint("error AcceptConsentRequest", err.Error())
		c.String(http.StatusUnprocessableEntity, str)
	}
	c.JSON(http.StatusOK, gin.H{
		"url_redirect": consentAcceptResponse.GetPayload().RedirectTo,
	})
}

func (o *oauth2Middleware) CreateOauthClient(c *gin.Context) {

	uuidGemerator, errUuid := uuid.NewGen().NewV4()
	if errUuid != nil {
		log.Fatal(errUuid.Error())
	}

	createOauthClientParams := admin.NewCreateOAuth2ClientParams()
	createOauthClientParams.WithBody(&hydraModels.OAuth2Client{
		ClientName: c.PostForm("client_name"),
		ClientID:   uuidGemerator.String(),
	})

	result, err := o.hydraAdmin.CreateOAuth2Client(createOauthClientParams)
	if err != nil {
		switch e := err.(type) {
		case (*admin.CreateOAuth2ClientConflict):
			c.JSON(http.StatusConflict, gin.H{
				"code":  http.StatusConflict,
				"error": e.GetPayload(),
			})
		case (*admin.CreateOAuth2ClientBadRequest):
			c.JSON(http.StatusBadRequest, gin.H{
				"code":  http.StatusBadRequest,
				"error": e.GetPayload(),
			})
		case (*admin.CreateOAuth2ClientInternalServerError):
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":  http.StatusInternalServerError,
				"error": e.GetPayload(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, result.GetPayload())
}
