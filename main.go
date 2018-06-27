package main

import (
	"bufio"
	"crypto/aes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	flag "github.com/ogier/pflag"
)

type configuration struct {
	Username           string
	Password           string
	KillSwitchPassword string
	PublicText         string
	PrivateURL         string
	Bind               string
	Token              string
	Realm              string
	HashKey            []byte
	BlockKey           []byte
	HTTPSOnlyCookie    bool
}

const (
	cookieName           = "auth"
	tokenName            = "token"
	authMsg              = "Succsessfully authenticated and stored session cookie."
	insecureConfirmation = "I am not running this over HTTP in production"
)

var (
	config    configuration
	secCookie *securecookie.SecureCookie

	hashKeyString    string
	blockKeyString   string
	killSwitchActive bool
)

func init() {
	flag.StringVarP(&config.Username, "username", "u", "", "A username that grants the user access to the secret face.")
	flag.StringVarP(&config.Password, "password", "p", "", "A password that grants the user access to the secret face.")
	flag.StringVar(&config.KillSwitchPassword, "killpass", "", "An alternate password that (when the flag is set, and when entered by the user) disables serving the secret face to all clients until the service is restarted.")
	flag.StringVarP(&config.PublicText, "public-text", "o", "404 Not Found", "Text to serve to unauthenticated users.")
	flag.StringVarP(&config.PrivateURL, "private", "c", "http://127.0.0.1:8001", "A URL to serve to authenticated users.")
	flag.StringVarP(&config.Bind, "bind", "b", "localhost:8000", "An address and port to bind to.")
	flag.StringVarP(&config.Token, "token", "t", uuid.New().String(), "The authentication token to verify authenticated users.")
	flag.StringVar(&hashKeyString, "hash-key", "", `A hexidecimal representation of a `+strconv.Itoa(aes.BlockSize)+` byte hash key, to secure authentication cookies.
	Do 'twoface generate-keys' to get some suitable keys.`)
	flag.StringVar(&blockKeyString, "block-key", "", `A hexidecimal representation of a `+strconv.Itoa(aes.BlockSize)+` byte block key, to secure authentication cookies.
	Do 'twoface generate-keys' to get some suitable keys`)
	flag.StringVarP(&config.Realm, "realm", "r", "", "A string that identifies the authentication popup.")
	flag.BoolVar(&config.HTTPSOnlyCookie, "secure-cookie", true, `Set the 'secure' flag on the auth cookie, if true cookies will not be sent by browsers over regular http.
		You should not be running this program in production over a non encrypted connection, so this is set to true by default.`)
}

func main() {
	var err error

	if len(os.Args) > 1 && os.Args[1] == "generate-keys" {
		log.Println("Generating two hexedecimally encoded", strconv.Itoa(aes.BlockSize), "byte keys...")
		log.Println(hex.EncodeToString(securecookie.GenerateRandomKey(aes.BlockSize)), "/", hex.EncodeToString(securecookie.GenerateRandomKey(aes.BlockSize)))
		return
	}

	flag.Parse()

	if hashKeyString == "" {
		config.HashKey = securecookie.GenerateRandomKey(aes.BlockSize)
	} else {
		config.HashKey, err = hex.DecodeString(hashKeyString)
		if err != nil {
			log.Panic("Couldn't decode hash key; ", err.Error())
		}
	}

	if blockKeyString == "" {
		config.BlockKey = securecookie.GenerateRandomKey(aes.BlockSize)
	} else {
		config.BlockKey, err = hex.DecodeString(blockKeyString)
		if err != nil {
			log.Panic("Couldn't decode block key; ", err.Error())
		}
	}

	if config.Password == "" || config.Username == "" {
		fmt.Println("Please specify a username and password.")
		flag.Usage()
		return
	}

	if config.Realm == "" {
		log.Println("Realm not specified... Setting to", config.Bind)
		config.Realm = config.Bind
	}

	secCookie = securecookie.New(config.HashKey, config.BlockKey)

	log.Print(`

=======================================================================
WARNING! This program uses HTTP Basic Authentication.
If you do not secure this program's connection behind a TLS enabled reverse
proxy, initial authentication passwords will be sent in _plaintext_!
=======================================================================

`)

	// Users will have to set this to false to run over http, so this seems like
	// a good way to ward off some foolishness
	if !config.HTTPSOnlyCookie {
		fmt.Print(`Whoah there! You've set the secure cookie flag to false. This will allow browsers
to send your (admittedly encrypted) cookies over regular HTTP.

Type "` + insecureConfirmation + `" to continue: `)

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if scanner.Text() != insecureConfirmation {
			return
		}
	}

	privateRemote, err := url.Parse(config.PrivateURL)
	if err != nil {
		log.Panic("Couldn't parse private URL; ", err.Error())
	}
	proxy := httputil.NewSingleHostReverseProxy(privateRemote)

	http.HandleFunc("/", reverseProxyHandler(proxy))
	http.HandleFunc("/auth", basicAuth(authHandler, []byte(config.Username), []byte(config.Password), []byte(config.KillSwitchPassword), config.Realm))

	log.Println("Listening on", config.Bind)
	log.Panic(http.ListenAndServe(config.Bind, nil))
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		tokenName: config.Token,
	}

	if encoded, err := secCookie.Encode(cookieName, data); err == nil {
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
			Secure:   config.HTTPSOnlyCookie,
			MaxAge:   2147483647, // Maximum possible value, we don't want this to expire
		}
		http.SetCookie(w, cookie)
		w.Write([]byte(authMsg))
	} else {
		w.Write([]byte("Couldn't set cookie; " + err.Error()))
	}
}

func reverseProxyHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(cookieName); err == nil {
			value := make(map[string]string)
			err = secCookie.Decode(cookieName, cookie.Value, &value)
			if err == nil && subtle.ConstantTimeCompare([]byte(config.Token), []byte(value[tokenName])) == 1 && !killSwitchActive {
				p.ServeHTTP(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(config.PublicText))
	}
}

func basicAuth(handler http.HandlerFunc, actualUsername, actualPassword, killSwitchPassword []byte, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		username, password, ok := r.BasicAuth()

		if subtle.ConstantTimeCompare([]byte(password), killSwitchPassword) == 1 && string(killSwitchPassword) != "" {
			killSwitchActive = true
			log.Println("Kill switch activated by User Agent", r.UserAgent(), "with IP", r.RemoteAddr)
			w.Write([]byte(authMsg))
			return
		}

		if !ok || subtle.ConstantTimeCompare([]byte(username), actualUsername) != 1 || subtle.ConstantTimeCompare([]byte(password), actualPassword) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorised.\n"))
			return
		}

		handler(w, r)
	}
}
