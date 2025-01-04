package gsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewFromSettingJson(t *testing.T) {
	type args struct {
		fromFile string
		scope    string
	}
	tests := []struct {
		name    string
		args    args
		want    *Gsa
		wantErr bool
	}{
		{
			name: "test-linux-ok",
			args: args{
				fromFile: "test/service.json",
				scope:    "testscope",
			},
			wantErr: false,
			want: &Gsa{
				serviceAccountConfig: ServiceAccountConfig{
					Type:                    "serviceaccount",
					ProjectId:               "pojectid",
					PrivateKeyId:            "keyid",
					PrivateKey:              "privatekey",
					ClientEmail:             "email",
					ClientId:                "clientid",
					AuthUri:                 "authuri",
					TokenUri:                "tokenuri",
					AuthProviderX509CertUrl: "authcerturl",
					ClientX509CertUrl:       "clientcerturl",
					UniverseDomain:          "domain",
				},
				scope: "testscope",
			},
		},
		{
			name: "test-windows",
			args: args{
				fromFile: "c:\\non-existent\\service.json",
			},
			wantErr: true,
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UseJson(tt.args.fromFile, tt.args.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromSettingJson() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				return
			}
			if !reflect.DeepEqual(got.serviceAccountConfig, tt.want.serviceAccountConfig) {
				t.Errorf("NewFromSettingJson() \n%v \nwant \n%v", got, tt.want)
			}
		})
	}
}

func getTestPrivateKey(t *testing.T) string {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Error(err)
	}
	rsaKeyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Error(err)
	}
	pemBlock := pem.Block{
		Bytes: rsaKeyBytes,
	}
	return string(pem.EncodeToMemory(&pemBlock))
}

func TestGsa_CreateCustomToken(t *testing.T) {
	type fields struct {
		serviceAccountConfig ServiceAccountConfig
	}
	type args struct {
		scope string
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   *jwt.Token
	}{
		{
			name: "Unittest",
			fields: fields{
				serviceAccountConfig: ServiceAccountConfig{
					Type:                    "serviceaccount",
					ProjectId:               "pojectid",
					PrivateKeyId:            "keyid",
					PrivateKey:              getTestPrivateKey(t),
					ClientEmail:             "email",
					ClientId:                "clientid",
					AuthUri:                 "authuri",
					TokenUri:                "tokenuri",
					AuthProviderX509CertUrl: "authcerturl",
					ClientX509CertUrl:       "clientcerturl",
					UniverseDomain:          "domain",
				},
			},
			args: args{
				scope: "https://www.googleapis.com/auth/datastore",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gsa := &Gsa{
				serviceAccountConfig: tt.fields.serviceAccountConfig,
			}
			got, err := gsa.CreateCustomToken()
			if err != nil {
				t.Errorf("Gsa.CreateCustomToken(): %s", err)
			}
			t.Logf("Custom token:\n%s\n", got)
		})
	}
}

// test with actual data
func TestWithRealConfig(t *testing.T) {
	t.Skip() // Uncomment this and change the line below to match your config
	gsa, err := UseJson("service.json", "https://www.googleapis.com/auth/datastore")
	if err != nil {
		t.Error(err)
	}

	_, err = gsa.CreateCustomToken()
	if err != nil {
		t.Error(err)
	}

	firebaseToken, err := gsa.GetServiceToken()
	if err != nil {
		t.Error(err)
	}
	fmt.Println(firebaseToken)
}
