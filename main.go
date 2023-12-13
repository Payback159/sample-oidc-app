package main

//A simple oidc-client application that reads a configuration file for the oidc parameters.
//This provides an OIDC login workflow and displays all information from the OIDC after successful authentication in order to get a better understanding of the OIDC workflow.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// Configuration struct for the oidc parameters
type Configuration struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	IssuerURL    string   `json:"issuer_url"`
	Scopes       []string `json:"scopes"`
}

// Struct for the oidc token
type Token struct {
	AccessToken string `json:"access_token"`
}

// Struct for the oidc user info
type UserInfo struct {
	Sub string `json:"sub"`
}

// Struct for the oidc claims
type Claims struct {
	Sub string `json:"sub"`
}

// Struct for the oidc id token
type IDToken struct {
	Sub string `json:"sub"`
}

// Struct for the oidc client
type Client struct {
	Configuration Configuration
	Provider      *oidc.Provider
	Oauth2Config  oauth2.Config
}

// Function to read the configuration file
func (c *Client) ReadConfig() {
	jsonFile, err := os.Open("config.json")
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &c.Configuration)
}

// Function to create the oidc client
func (c *Client) CreateClient() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Configuration.IssuerURL)
	if err != nil {
		log.Fatal(err)
	}
	c.Provider = provider
	c.Oauth2Config = oauth2.Config{
		ClientID:     c.Configuration.ClientID,
		ClientSecret: c.Configuration.ClientSecret,
		RedirectURL:  c.Configuration.RedirectURL,
		Endpoint:     c.Provider.Endpoint(),
		Scopes:       c.Configuration.Scopes,
	}
}

// Function to create the oidc login url
func (c *Client) CreateLoginURL() string {
	return c.Oauth2Config.AuthCodeURL("state")
}

// Function to exchange the oidc code for a token
func (c *Client) ExchangeCode(code string) *oauth2.Token {
	ctx := context.Background()
	token, err := c.Oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	return token
}

// Function to get the oidc token
func (c *Client) GetToken(token *oauth2.Token) *Token {
	return &Token{
		AccessToken: token.AccessToken,
	}
}

// Function to get the oidc user info
func (c *Client) GetUserInfo(token *oauth2.Token) *UserInfo {
	ctx := context.Background()
	userInfo, err := c.Provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		log.Fatal(err)
	}

	var userInfoStruct UserInfo
	userInfo.Claims(&userInfoStruct)
	return &userInfoStruct
}

// Function to get the oidc id token
func (c *Client) GetIDToken(token *oauth2.Token) *IDToken {
	ctx := context.Background()
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Fatal("No id_token field in oauth2 token.")
	}
	idToken, err := c.Provider.Verifier(&oidc.Config{ClientID: c.Configuration.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		log.Fatal(err)
	}
	var idTokenStruct IDToken
	idToken.Claims(&idTokenStruct)
	return &idTokenStruct
}

// Function to get the oidc claims
func (c *Client) GetClaims(token *oauth2.Token) *Claims {
	ctx := context.Background()
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Fatal("No id_token field in oauth2 token.")
	}
	idToken, err := c.Provider.Verifier(&oidc.Config{ClientID: c.Configuration.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		log.Fatal(err)
	}

	//iterate over the id token response, build a map of claims and return it
	var claimsStruct Claims
	idToken.Claims(&claimsStruct)
	return &claimsStruct
}

// Function to parse the whole jwt token without struct
func (c *Client) GetOIDCInfo(code string) {
	token := c.ExchangeCode(code)
	tokenStruct := c.GetToken(token)
	userInfoStruct := c.GetUserInfo(token)
	idTokenStruct := c.GetIDToken(token)
	claimsStruct := c.GetClaims(token)
	fmt.Println("Token: ", tokenStruct)
	fmt.Println("UserInfo: ", userInfoStruct)
	fmt.Println("IDToken: ", idTokenStruct)
	fmt.Println("Claims: ", claimsStruct)

}

// Function to handle the oidc login workflow
func (c *Client) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	switch r.Method {
	case "GET":
		http.Redirect(w, r, c.CreateLoginURL(), http.StatusSeeOther)
	case "POST":
		code := r.FormValue("code")
		c.GetOIDCInfo(code)
	}
}

// Function to handle the oidc callback
func (c *Client) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/callback" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	switch r.Method {
	case "GET":
		code := r.FormValue("code")
		c.GetOIDCInfo(code)
		//Send 200 OK response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Login successful"))

	}
}

// Function to handle the oidc logout
func (c *Client) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/logout" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	switch r.Method {
	case "GET":
		http.Redirect(w, r, c.Provider.Endpoint().AuthURL+"?logout="+c.Configuration.RedirectURL, http.StatusSeeOther)
	}
}

// Function to handle the oidc callback
func (c *Client) HandleCallbackLogout(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/callback_logout" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	switch r.Method {
	case "GET":
		c.HandleLogin(w, r)
	}
}

// Main function
func main() {
	client := Client{}
	client.ReadConfig()
	client.CreateClient()
	http.HandleFunc("/", client.HandleLogin)
	http.HandleFunc("/callback", client.HandleCallback)
	http.HandleFunc("/logout", client.HandleLogout)
	http.HandleFunc("/callback_logout", client.HandleCallbackLogout)
	fmt.Println("Starting server on port 8080")
	http.ListenAndServe(":8080", nil)
}
