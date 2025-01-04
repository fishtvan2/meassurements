package gsa

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type customClaim struct {
	Scope     string `json:"scope"`
	UserID    string `json:"uid"`
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func (c customClaim) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Audience}, nil
}

func (c customClaim) GetExpirationTime() (*jwt.NumericDate, error) {
	time := time.Unix(c.ExpiresAt, 0)
	return jwt.NewNumericDate(time), nil
}

func (c customClaim) GetIssuedAt() (*jwt.NumericDate, error) {
	time := time.Unix(c.IssuedAt, 0)
	return jwt.NewNumericDate(time), nil
}

func (c customClaim) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c customClaim) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, fmt.Errorf("no such field")
}

func (c customClaim) GetSubject() (string, error) {
	return c.Subject, nil
}
