package main

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/subtle"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	flag "github.com/ogier/pflag"
)

type configuration struct {
	Username   string
	Password   string
	PublicText string
	PrivateURL string
	Bind       string
	Token      string
	Realm      string
}

const cookieName = "auth"

var (
	config       configuration
	secureCookie *securecookie.SecureCookie
)

func init() {
	flag.StringVarP(&config.Username, "username", "u", "", "A username that grants the user access to the secret face.")
	flag.StringVarP(&config.Password, "password", "p", "", "A password that grants the user access to the secret face.")
	flag.StringVarP(&config.PublicText, "public-text", "o", "404 Not Found", "Text to serve to unauthenticated users.")
	flag.StringVarP(&config.PrivateURL, "private", "c", "http://127.0.0.1:8001", "A URL to serve to authenticated users.")
	flag.StringVarP(&config.Bind, "bind", "b", "localhost:8000", "An address and port to bind to.")
	flag.StringVarP(&config.Token, "token", "t", uuid.New().String(), "The authentication token to verify authenticated users.")
	flag.StringVarP(&config.Realm, "realm", "r", "", "A string that identifies the authentication popup.")
}

func main() {
	flag.Parse()

	secureCookie = securecookie.New(securecookie.GenerateRandomKey(aes.BlockSize), securecookie.GenerateRandomKey(aes.BlockSize))

	if config.Password == "" || config.Username == "" {
		log.Panic("Please specify a username and password.")
	}

	if config.Realm == "" {
		log.Println("Realm not specified... Setting to", config.Bind)
		config.Realm = config.Bind
	}

	log.Print(`

=======================================================================
WARNING! This program uses HTTP Digest Authentication.
If you do not secure its connection behind a TLS enabled reverse proxy,
initial authentication passwords will be sent in _plaintext_!
=======================================================================

`)
	privateRemote, err := url.Parse(config.PrivateURL)
	if err != nil {
		log.Panic("Couldn't parse private URL; ", err.Error())
	}
	proxy := httputil.NewSingleHostReverseProxy(privateRemote)

	http.HandleFunc("/", reverseProxyHandler(proxy))
	http.HandleFunc("/auth", basicAuth(authHandler, config.Username, config.Password, config.Realm))

	log.Println("Listening on", config.Bind)
	log.Panic(http.ListenAndServe(config.Bind, nil))
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		"token": config.Token,
	}

	if encoded, err := secureCookie.Encode(cookieName, data); err == nil {
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   2147483647, // Maximum possible value, we don't want this to expire
		}
		http.SetCookie(w, cookie)
		w.Write([]byte("Succsessfully authenticated and stored session cookie."))
	} else {
		w.Write([]byte("Couldn't set cookie; " + err.Error()))
	}
}

func reverseProxyHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(cookieName); err == nil {
			value := make(map[string]string)
			if err = secureCookie.Decode(cookieName, cookie.Value, &value); err == nil {
				p.ServeHTTP(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte(config.PublicText))
	}
}

func basicAuth(handler http.HandlerFunc, username, password, realm string) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		u, p, ok := r.BasicAuth()
		// Stops length-based timing attacks... Weak hash function is ok because we
		// just want constant length
		user := md5.Sum([]byte(u))
		pass := md5.Sum([]byte(p))
		actualUsername := md5.Sum([]byte(username))
		actualPassword := md5.Sum([]byte(password))

		if !ok || subtle.ConstantTimeCompare(user[:], actualUsername[:]) != 1 || subtle.ConstantTimeCompare(pass[:], actualPassword[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorised.\n"))
			return
		}

		handler(w, r)
	}
}
