package main

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

const clientID = "bca3ef2d"
const clientSecret = "e5e6e4ed"
const redirectUri = "http://localhost:9094/callback"

func BasicAuth() string {
	auth := clientID + ":" + clientSecret
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		client := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   "http://localhost:9096/oauth2/auth",
				TokenURL:  "http://localhost:9096/oauth2/token",
				AuthStyle: 0,
			},
			RedirectURL: redirectUri,
		}
		authUri := client.AuthCodeURL("")
		http.Redirect(w, r, authUri, http.StatusFound)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")

		client := &http.Client{}
		data := url.Values{}

		//set parameters
		data.Set("grant_type", "authorization_code")
		data.Add("code", code)
		data.Add("redirect_uri", redirectUri)

		tokenEndpoint := "http://localhost:9096/oauth2/token"
		request, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
		if err != nil {
			log.Fatalln(err)
		}
		//set headers
		request.Header.Set("accept", "application/json")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		request.Header.Set("Authorization", "Basic "+BasicAuth())

		resp, err := client.Do(request)
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		w.Write(body)
	})

	http.HandleFunc("/refresh-access-token", func(w http.ResponseWriter, r *http.Request) {
		refreshToken := r.URL.Query().Get("refresh_token")

		client := &http.Client{}
		data := url.Values{}
		data.Set("refresh_token", refreshToken)

		//set parameters
		data.Set("grant_type", "refresh_token")

		tokenEndpoint := "http://localhost:9096/oauth2/token"
		request, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
		if err != nil {
			log.Fatalln(err)
		}
		//set headers
		request.Header.Set("accept", "application/json")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		request.Header.Set("Authorization", "Basic "+BasicAuth())

		resp, err := client.Do(request)
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		w.Write(body)
	})

	http.HandleFunc("/revoke-access-token", func(w http.ResponseWriter, r *http.Request) {
		// refreshToken := r.URL.Query().Get("refresh_token")
		accessToken := r.URL.Query().Get("access_token")

		client := &http.Client{}
		data := url.Values{}
		// data.Set("refresh_token", refreshToken)
		data.Set("access_token", accessToken)

		tokenEndpoint := "http://localhost:9096/oauth2/revocation"
		request, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
		if err != nil {
			log.Fatalln(err)
		}
		//set headers
		request.Header.Set("accept", "application/json")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		request.Header.Set("Authorization", "Basic "+BasicAuth())

		resp, err := client.Do(request)
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		w.Write(body)
	})

	log.Fatal(http.ListenAndServe(":9094", nil))
}
