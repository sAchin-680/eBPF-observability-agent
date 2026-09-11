// Command go-api is a sample HTTPS service used to verify tracing of
// unmodified applications. It contains no instrumentation.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type user struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

var users = []user{{ID: 1, Name: "ada"}, {ID: 2, Name: "grace"}, {ID: 3, Name: "katherine"}}

func main() {
	addr := envOr("ADDR", ":8443")
	cert := envOr("CERT", "../certs/cert.pem")
	key := envOr("KEY", "../certs/key.pem")

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, user{ID: len(users) + 1, Name: "new"})
			return
		}
		writeJSON(w, users)
	})

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		if id == "999" {
			http.Error(w, "no such user", http.StatusNotFound)
			return
		}
		writeJSON(w, user{ID: 1, Name: "ada"})
	})

	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.Write([]byte("slow"))
	})

	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "deliberate failure", http.StatusInternalServerError)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("go-api listening on %s", addr)
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
