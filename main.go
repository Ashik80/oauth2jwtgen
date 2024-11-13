package main

import (
	"encoding/json"
	"fmt"
	"github.com/Ashik80/oauth2jwtgen/accessor"
	"github.com/Ashik80/oauth2jwtgen/manager"
	"net/http"
)

type PasswordRequest struct {
	GrantType string `json:"grant_type"`
	Password  string `json:"password"`
	Username  string `json:"username"`
}

func main() {
	m := manager.NewHSKeyManager()
	// for RSA keys add the path to the key
	// Eg:
	//     m.AddKey("key1", "keys/private.key")
	m.AddKey("key1", "sdfsdfsdfsdfasdfdsfasdfsdfasdf")

	http.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			fmt.Println("[ERROR] error parsing body:", err)
		}

		password := r.FormValue("password")
		username := r.FormValue("username")
		grantType := r.FormValue("grant_type")

		// Hash password and save it to the database at this point
		fmt.Println(password)
		fmt.Println(username)
		fmt.Println(grantType)

		validity := &accessor.Validity{
			ExpiresIn: 15 * 60, // 15 minutes
		}
		// Parameter validity can be nil. Default validity 10 minutes.
		access, err := accessor.NewHS256Access("key1", m, validity)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		claims := accessor.GenerateDefaultClaims(access, username)
		token, err := accessor.NewToken(access, claims)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	})

	http.ListenAndServe(":4040", nil)
}
