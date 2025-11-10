package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/dangdinh2405/auth-JWT-Golang/internal/data"
	"github.com/dangdinh2405/auth-JWT-Golang/internal/http"
	"github.com/dangdinh2405/auth-JWT-Golang/internal/store"
	"github.com/dangdinh2405/auth-JWT-Golang/internal/middleware"

)

func main() {
	godotenv.Load()
	// Production:

	// gin.SetMode(gin.ReleaseMode) #Deloy must turn on
	// nhớ cấu hình reverse proxy (X-Forwarded-Proto) nếu đứng sau CDN/Load Balancer

	r := gin.Default()
	r.SetTrustedProxies(nil)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	db, err := data.NewMongo(os.Getenv("MONGO_CONECTION"))
	if err != nil {
		log.Fatal(err)
	}

	dbName := os.Getenv("MONGO_DB_NAME")
	if dbName == "" {
		dbName = "auth"
	}
	userCol := db.DB(dbName).Collection("users")
	sessionsCol := db.DB(dbName).Collection("session")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := store.EnsureSessionIndexes(ctx, sessionsCol); err != nil {
		log.Fatal(err)
	}
	
	http.AuthRoutes(r, db, dbName)

	r.Use(middleware.RequireAuth(userCol))
	http.UserRoutes(r)

	defer db.Close()

	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}