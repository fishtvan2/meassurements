package gsa

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Gsa struct {
	serviceAccountConfig ServiceAccountConfig
	scope                string
}

type ServiceAccountConfig struct {
	Type                    string `json:"type"`
	ProjectId               string `json:"project_id"`
	PrivateKeyId            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientId                string `json:"client_id"`
	AuthUri                 string `json:"auth_uri"`
	TokenUri                string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl       string `json:"client_x509_cert_url"`
	UniverseDomain          string `json:"universe_domain"`
}

type Oauth2Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	ExpiresIn    int64     `json:"expires_in,omitempty"`
}

type AccessToken struct {
	Token     string
	ExpiresIn int64
}

func UseStruct(fromConfig ServiceAccountConfig, scope string) *Gsa {
	return &Gsa{
		serviceAccountConfig: fromConfig,
		scope:                scope,
	}
}

func UseJson(fromFile string, scope string) (*Gsa, error) {
	jsonFile, err := os.Open(fromFile)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	content, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var config ServiceAccountConfig
	err = json.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}
	gsa := Gsa{
		serviceAccountConfig: config,
		scope:                scope,
	}

	return &gsa, nil
}

func (gsa *Gsa) CreateCustomToken() (string, error) {
	now := time.Now()
	expires := now.Add(3600 * time.Second)
	claim := customClaim{
		Scope:     gsa.scope,
		UserID:    gsa.serviceAccountConfig.ClientId,
		Issuer:    gsa.serviceAccountConfig.ClientEmail,
		Subject:   gsa.serviceAccountConfig.ClientEmail,
		Audience:  gsa.serviceAccountConfig.TokenUri,
		IssuedAt:  now.Unix(),
		ExpiresAt: expires.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	token.Header["kid"] = gsa.serviceAccountConfig.PrivateKeyId

	pemBlock, _ := pem.Decode([]byte(gsa.serviceAccountConfig.PrivateKey))

	types, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return "", err
	}
	return token.SignedString(types)
}

func (gsa *Gsa) GetServiceToken() (AccessToken, error) {
	token, err := gsa.getOauthToken()
	if err != nil {
		return AccessToken{}, err
	}
	return AccessToken{
		Token:     token.AccessToken,
		ExpiresIn: token.ExpiresIn,
	}, nil
}

func (gsa *Gsa) getOauthToken() (Oauth2Token, error) {
	customToken, err := gsa.CreateCustomToken()
	if err != nil {
		return Oauth2Token{}, err
	}

	body := url.Values{}
	body.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	body.Set("assertion", customToken)

	response, err := http.Post(gsa.serviceAccountConfig.TokenUri,
		"application/x-www-form-urlencoded",
		strings.NewReader(body.Encode()))

	if err != nil {
		return Oauth2Token{}, err
	}

	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return Oauth2Token{}, err
	}

	if response.StatusCode != http.StatusOK {
		return Oauth2Token{}, fmt.Errorf("could not get token, %s", response.Status)
	}

	var oauthToken Oauth2Token
	err = json.Unmarshal(bodyBytes, &oauthToken)
	if err != nil {
		return Oauth2Token{}, err
	}

	return oauthToken, nil
}
