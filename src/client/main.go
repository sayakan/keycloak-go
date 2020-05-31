package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strings"

	"learn.oauth.client/model"
)

var config = struct {
	appID               string
	appPassword         string
	authURL             string
	logout              string
	afterLogoutRedirect string
	authCodeCallback    string
	tokenEndpoint       string
}{
	appID:               "billingApp",
	appPassword:         "a538e648-a32c-4302-bef7-652563da0745",
	authURL:             "http://10.100.196.60:8080/auth/realms/learningApp/protocol/openid-connect/auth",
	logout:              "http://10.100.196.60:8080/auth/realms/learningApp/protocol/openid-connect/logout",
	afterLogoutRedirect: "http://localhost:8080",
	authCodeCallback:    "http://localhost:8080/authCodeRedirect",
	tokenEndpoint:       "http://10.100.196.60:8080/auth/realms/learningApp/protocol/openid-connect/token",
}
var t = template.Must(template.ParseFiles("template/index.html"))

// AppVar is Application private variable
type AppVar struct {
	AuthCode     string
	SessionState string
	AccessToken  string
	RefreshToken string
	Scope        string
}

var appVar = AppVar{}

func main() {
	fmt.Println("hello")
	http.HandleFunc("/", enabledLog(home))
	http.HandleFunc("/login", enabledLog(login))
	http.HandleFunc("/exchangeToken", enabledLog(exchangeToken))
	http.HandleFunc("/logout", enabledLog(logout))
	http.HandleFunc("/authCodeRedirect", enabledLog(authCodeRedirect))
	http.ListenAndServe(":8080", nil)
}

// log for processing
func enabledLog(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		handlerName := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()

		log.SetPrefix(handlerName + " ")
		log.Println("--> " + handlerName)

		log.Printf("request : %+v\n", r.RequestURI)
		handler(w, r)
		log.Println("<-- " + handlerName + "\n")
	}
}

func home(w http.ResponseWriter, r *http.Request) {

	t.Execute(w, appVar)

}

func login(w http.ResponseWriter, r *http.Request) {
	// create a redirect URL for auth
	req, err := http.NewRequest("GET", config.authURL, nil)
	if err != nil {
		log.Print(err)
		return
	}

	// request a token
	// return value ex：http://localhost:8080/?session_state=a3eefcb9-5b8a-4fd5-a67b-b8fd845b7601&code=8b5dceda-1d55-443a-adbc-327d437b86e0.a3eefcb9-5b8a-4fd5-a67b-b8fd845b7601.e9cede5d-1890-4208-8082-ea82e98f6958
	qs := url.Values{}
	qs.Add("state", "1234")
	qs.Add("client_id", config.appID)
	qs.Add("response_type", "code")
	qs.Add("redirect_uri", config.authCodeCallback)

	req.URL.RawQuery = qs.Encode()
	http.Redirect(w, r, req.URL.String(), http.StatusFound)
}

func authCodeRedirect(w http.ResponseWriter, r *http.Request) {

	appVar.AuthCode = r.URL.Query().Get("code")
	appVar.SessionState = r.URL.Query().Get("session_state")
	r.URL.RawQuery = ""
	fmt.Printf("Request queries: %+v\n", appVar)

	http.Redirect(w, r, "http://localhost:8080", http.StatusFound)

}

func logout(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	q.Add("redirect_uri", config.afterLogoutRedirect)

	logoutURL, err := url.Parse(config.logout)
	if err != nil {
		log.Println(err)
	}
	logoutURL.RawQuery = q.Encode()
	// appVar = AppVar{}

	http.Redirect(w, r, logoutURL.String(), http.StatusFound)

}

func exchangeToken(w http.ResponseWriter, r *http.Request) {
	// Request

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", appVar.AuthCode)
	form.Add("redirect_uri", config.authCodeCallback)
	form.Add("client_id", config.appID)
	req, err := http.NewRequest("POST", config.tokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		log.Println(err)
		return
	}

	req.SetBasicAuth(config.appID, config.appPassword)

	// Client
	c := http.Client{}
	res, err := c.Do(req)
	if err != nil {
		log.Print("coundnt get access token: ", err)
		return
	}

	// ProcessResponse
	byteBody, err := ioutil.ReadAll(res.Body)

	defer res.Body.Close()

	if err != nil {
		log.Println("coundn't get access token: ", err)
		return
	}

	// integrate access token and app
	accessTokenResponse := &model.AccessTokenResponse{}
	json.Unmarshal(byteBody, accessTokenResponse)

	appVar.AccessToken = accessTokenResponse.AccessToken
	appVar.RefreshToken = accessTokenResponse.RefreshToken
	appVar.Scope = accessTokenResponse.Scope

	log.Println(string(byteBody))

	t.Execute(w, appVar)
}
