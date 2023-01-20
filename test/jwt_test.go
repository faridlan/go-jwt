package test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Message struct {
	Status string `json:"status,omitempty"`
	Data   string `json:"data,omitempty"`
}

func HelloWorld(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Add("content-type", "application/json")
	var message Message

	decoder := json.NewDecoder(request.Body)
	err := decoder.Decode(&message)
	if err != nil {
		panic(err)
	}

	encoder := json.NewEncoder(writer)
	err = encoder.Encode(message)
	if err != nil {
		panic(err)
	}
}

func TestHelloWorld(t *testing.T) {

	mux := http.NewServeMux()
	mux.HandleFunc("/home", verifyJWT(HelloWorld))

	server := http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

var SecretKey = []byte("anjingadalahbinatang")

func GenerateJWT() (string, error) {

	token := jwt.New(jwt.SigningMethodEdDSA)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(10 * time.Minute)
	claims["authorized"] = true
	claims["user"] = "username"

	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyJWT(endpointHandler func(writer http.ResponseWriter, request *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {

		if request.Header["Token"] != nil {
			token, err := jwt.Parse(request.Header["Token"][0], func(token *jwt.Token) (any, error) {
				_, ok := token.Method.(*jwt.SigningMethodECDSA)
				if !ok {
					writer.WriteHeader(http.StatusUnauthorized)
					_, err := writer.Write([]byte("you're Unauthorized!"))
					if err != nil {
						return nil, err
					}
				}
				return "", nil
			})

			if err != nil {
				writer.WriteHeader(http.StatusUnauthorized)
				_, err2 := writer.Write([]byte("You're Unauthorized due to error parsing the JWT"))
				if err2 != nil {
					return
				}
			}

			if token.Valid {
				endpointHandler(writer, request)
			} else {
				writer.WriteHeader(http.StatusUnauthorized)
				_, err := writer.Write([]byte("You're Unauthorized due to invalid token"))
				if err != nil {
					return
				}
			}
		} else {
			writer.WriteHeader(http.StatusUnauthorized)
			_, err := writer.Write([]byte("You're Unauthorized due to No token in the header"))
			if err != nil {
				return
			}
		}

	})
}
