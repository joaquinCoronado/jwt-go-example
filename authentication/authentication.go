package authentication

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/joaquinCoronado/jwt-example/model"
	"io/ioutil"
	"log"
	"time"
)

var (
	privateKey *rsa.PrivateKey
	publicKey *rsa.PublicKey
)

func init ( ) {
	privateBytes, err := ioutil.ReadFile("./private.rsa")

	if err != nil {
		log.Fatal("Error al leer el archivo private.rsa")
	}

	publicBytes, err := ioutil.ReadFile("./public.rsa.pud")

	if err != nil {
		log.Fatal("Error al leer el archivo public.rsa.pud")
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal("erro al crear llave privada")
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal("erro al crear llave privada")
	}

}

func GenerateJWT(user model.User) string {

	claims := model.Claim{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer: "Ejemplo JWT",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	result, err := token.SignedString(privateKey)

	if err != nil {
		log.Fatal("No se pudo firmar el token")
	}

	return result
}