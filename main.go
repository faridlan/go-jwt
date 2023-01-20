package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/novalagung/gubrak/v2"
)

type M map[string]any

type key string

const (
	keyString key = "userInfo"
)

type MyClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Group    string `json:"group,omitempty"`
}

var APPLICATION_NAME = "GO JWT"
var LOGIN_EXPIRATION_DURATION = time.Duration(1) * time.Hour
var JTWT_SIGNING_METHOD = jwt.SigningMethodHS256
var JWT_SIGNATURE_KEY = []byte("anjingadalahbinatang")

type CustomMux struct {
	http.ServeMux
	Middlewares []func(next http.Handler) http.Handler
}

func (c *CustomMux) RegisterMiddleware(next func(nex http.Handler) http.Handler) {
	c.Middlewares = append(c.Middlewares, next)
}

func (c *CustomMux) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var current http.Handler = &c.ServeMux

	for _, next := range c.Middlewares {
		current = next(current)
	}

	current.ServeHTTP(writer, request)
}

func main() {

	mux := new(CustomMux)
	mux.RegisterMiddleware(MiddlewareJWTAuthorization)

	mux.HandleFunc("/login", HandlerLogin)
	mux.HandleFunc("/index", HandlerIndex)

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Println("Starting server at", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}

}

func HandlerLogin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(writer, "Unsuported http method", http.StatusBadRequest)
		return
	}

	username, password, ok := request.BasicAuth()
	if !ok {
		http.Error(writer, "Invalid username or password", http.StatusBadRequest)
		return
	}

	ok, userInfo := AuthenticateUser(username, password)
	if !ok {
		http.Error(writer, "invalid username or password", http.StatusBadRequest)
		return
	}

	claims := MyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: APPLICATION_NAME,
			ExpiresAt: &jwt.NumericDate{
				Time: time.Now().Add(LOGIN_EXPIRATION_DURATION),
			},
			// ExpiresAt: time.Now().Add(LOGIN_EXPIRATION_DURATION).Unix(),
		},
		Username: userInfo["username"].(string),
		Email:    userInfo["email"].(string),
		Group:    userInfo["group"].(string),
	}

	token := jwt.NewWithClaims(JTWT_SIGNING_METHOD, claims)

	signedToken, err := token.SignedString(JWT_SIGNATURE_KEY)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	tokenString, err := json.Marshal(M{"token": signedToken})
	if err != nil {
		panic(err)
	}

	writer.Write([]byte(tokenString))
}

func AuthenticateUser(username, password string) (bool, M) {
	basePath, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	dbPath := filepath.Join(basePath, "users.json")
	buf, err := ioutil.ReadFile(dbPath)
	if err != nil {
		panic(err)
	}

	data := make([]M, 0)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return false, nil
	}

	res := gubrak.From(data).Find(func(each M) bool {
		return each["username"] == username && each["password"] == password
	}).Result()

	if res != nil {
		resM := res.(M)
		delete(resM, "password")
		return true, resM
	}

	return false, nil
}

func MiddlewareJWTAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/login" {
			next.ServeHTTP(writer, request)
			return
		}

		authorizationHeader := request.Header.Get("Authorization")
		if !strings.Contains(authorizationHeader, "Bearer") {
			http.Error(writer, "Invalid Token", http.StatusBadRequest)
			return
		}

		tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("signing method invalid")
			} else if method != JTWT_SIGNING_METHOD {
				return nil, fmt.Errorf("signing method invalid")
			}

			return JWT_SIGNATURE_KEY, nil
		})
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(writer, err.Error(), http.StatusBadRequest)
		}

		ctx := context.WithValue(context.Background(), keyString, claims)
		request = request.WithContext(ctx)

		next.ServeHTTP(writer, request)
	})

}

func HandlerIndex(writer http.ResponseWriter, request *http.Request) {
	userInfo := request.Context().Value("userInfo").(jwt.MapClaims)
	message := fmt.Sprintf("hello %s (%s)", userInfo["username"], userInfo["group"])
	writer.Write([]byte(message))
}
