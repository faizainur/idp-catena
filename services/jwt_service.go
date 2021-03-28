package services

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

type JWTService struct {
	PrivateKey *rsa.PrivateKey
}

func (j *JWTService) GenerateToken(claims map[string]interface{}) ([]byte, error) {

	tokenClaims := jwt.New()

	for key, val := range claims {
		switch key {
		case "iss":
			tokenClaims.Set(jwt.IssuerKey, val)
		case "sub":
			tokenClaims.Set(jwt.SubjectKey, val)
		case "aud":
			tokenClaims.Set(jwt.AudienceKey, val)
		case "exp":
			tokenClaims.Set(jwt.ExpirationKey, val)
		case "iat":
			tokenClaims.Set(jwt.IssuedAtKey, val)
		case "nbf":
			tokenClaims.Set(jwt.NotBeforeKey, val)
		case "jti":
			tokenClaims.Set(jwt.JwtIDKey, val)
		default:
			tokenClaims.Set(key, val)
		}
	}

	token, err := jwt.Sign(tokenClaims, jwa.RS256, j.PrivateKey)

	return token, err

}

func (j *JWTService) ValidateToken(token []byte) (bool, map[string]interface{}) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload, err := jwt.Parse(
		token,
		jwt.WithValidate(true),
		jwt.WithVerify(jwa.RS256, &j.PrivateKey.PublicKey),
	)

	if err != nil {
		return false, nil
	}

	payloadMap, err := payload.AsMap(ctx)
	if err != nil {
		panic(err)
	}
	return true, payloadMap

}
