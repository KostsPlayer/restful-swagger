package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"strings"
	"time"

	"piii/database"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

var jwtKey = []byte("your_secret_key")

type Categories struct {
	ID    		int			`json:"id"`
	Category  	string		`json:"category"`
	About 		string		`json:"about"`
}

func main() {

	defer database.DB.Close()
	db := database.DB
	

	type User struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

    router := mux.NewRouter()

	

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Here you should add your database logic to check user credentials
		// For simplicity, we assume the user is authenticated if username and password are not empty
		if user.Username != "" && user.Password != "" {
			tokenString, err := GenerateJWT()
			if err != nil {
				http.Error(w, "Error generating token", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	})

	router.HandleFunc("/categories", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
            // Handle preflight request
            w.Header().Set("Access-Control-Allow-Origin", "https://go-restful-swagger-client.vercel.app")
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
            return
        }
		switch r.Method {
		case "GET":
			idStr := r.URL.Query().Get("id")
			if idStr != "" {
				getCategory(db, w, r)
			} else {
				getCategories(db, w, r)
			}
		case "POST":
			bearerToken := r.Header.Get("Authorization")
			strArr := strings.Split(bearerToken, " ")
			if len(strArr) == 2 {
				isValid, _ := ValidateToken(strArr[1])
				if isValid {
					createCategory(db, w, r)
				} else {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				}
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
		case "PUT":
			updateCategory(db, w, r)
		case "DELETE":
			deleteCategory(db, w, r)
		default:
			http.Error(w, "Unsupported HTTP Method", http.StatusBadRequest)
		}
	})

	 // Set up CORS middleware
	 c := cors.New(cors.Options{
		AllowedOrigins: []string{"https://go-restful-swagger-client.vercel.app"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"}, // Tambahkan method-method yang diperlukan
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		Debug: true,
	})
	
	
    handler := c.Handler(router)
	
	fmt.Println("Server is running on https://golang-swagger-server.vercel.app")
	log.Fatal(http.ListenAndServe(":8082", handler))
}

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return false, err
	}

	return token.Valid, nil
}

func getCategory(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	//panic("unimplemented")
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid tickets ID", http.StatusBadRequest)
		return
	}

	row := db.QueryRow("SELECT * FROM categories WHERE id = $1", id)

	var p Categories
	if err := row.Scan(&p.ID, &p.Category, &p.About); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Category not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func getCategories(db *sql.DB, w http.ResponseWriter, _ *http.Request) {
	rows, err := db.Query("SELECT * FROM categories")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var Category []Categories
	for rows.Next() {
		var p Categories
		if err := rows.Scan(&p.ID, &p.Category, &p.About); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		Category = append(Category, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Category)
}

func createCategory(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var p Categories
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var id int
	
	err := db.QueryRow("INSERT INTO categories (category, about) VALUES ($1, $2) RETURNING id", p.Category, p.About).Scan(&id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.ID = id
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func updateCategory(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var p Categories
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := db.Exec("UPDATE categories SET category = $1, about = $2 WHERE id = $3", p.Category, p.About, p.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteCategory(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	if _, err := db.Exec("DELETE FROM categories WHERE id = $1", id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
