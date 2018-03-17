package main

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/hex"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	auth "github.com/abbot/go-http-auth"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	flag "github.com/ogier/pflag"
)

type configuration struct {
	Password   string
	PublicText string
	PrivateURL string
	Bind       string
	Token      string
}

const cookieName = "auth"

var (
	config       configuration
	secureCookie *securecookie.SecureCookie
)

func init() {
	flag.StringVarP(&config.Password, "password", "p", "", "A password that grants the user access to the secret face.")
	flag.StringVarP(&config.PublicText, "public-text", "o", "404 File Not Found", "Text to serve to unauthenticated users.")
	flag.StringVarP(&config.PrivateURL, "private", "c", "http://127.0.0.1:8001", "A URL to serve to authenticated users.")
	flag.StringVarP(&config.Bind, "bind", "b", "localhost:8000", "An address and port to bind to.")
	flag.StringVarP(&config.Token, "token", "t", uuid.New().String(), "The authentication token to verify authenticated users.")
}

func main() {
	flag.Parse()

	secureCookie = securecookie.New(securecookie.GenerateRandomKey(aes.BlockSize), securecookie.GenerateRandomKey(aes.BlockSize))

	if config.Password == "" {
		log.Panic("Please specify a password.")
	}

	log.Print(`

=======================================================================
WARNING! This program uses HTTP Digest Authentication.
If you do not secure its connection behind a TLS enabled reverse proxy,
initial authentication passwords will be sent in _plaintext_!
=======================================================================

`)

	a := auth.NewDigestAuthenticator(config.Bind, func(user, realm string) string {
		// Yes, I know http digest auth is insecure without TLS
		// Yes, I know about the replay attacks
		sum := md5.Sum([]byte(user + ":" + config.Bind + ":" + config.Password))
		return hex.EncodeToString(sum[:])
	})

	privateRemote, err := url.Parse(config.PrivateURL)
	if err != nil {
		log.Panic("Couldn't parse private URL; ", err.Error())
	}
	proxy := httputil.NewSingleHostReverseProxy(privateRemote)

	http.HandleFunc("/", reverseProxyHandler(proxy))
	http.HandleFunc("/auth", a.Wrap(authHandler))

	log.Println("Listening on", config.Bind)
	log.Panic(http.ListenAndServe(config.Bind, nil))
}

func switchingHandler(w http.ResponseWriter, r *http.Request) {

}

func authHandler(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	data := map[string]string{
		"token": config.Token,
	}

	log.Println(config.Token)

	if encoded, err := secureCookie.Encode(cookieName, data); err == nil {
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		w.Write([]byte("Succsessfully authenticated and stored session cookie as " + r.Username))
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

		w.Write([]byte(config.PublicText))
	}
}
