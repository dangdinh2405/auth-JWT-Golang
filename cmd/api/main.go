package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	// gin.SetMode(gin.ReleaseMode) #Deloy must turn on

    r := gin.Default()
	r.SetTrustedProxies(nil)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
    if err := r.Run(":" + port); err != nil {
        log.Fatal(err)
    }
}