package http

import (
	"github.com/gin-gonic/gin"
	"github.com/dangdinh2405/auth-JWT-Golang/internal/data"
	"github.com/dangdinh2405/auth-JWT-Golang/internal/handler"
)

func AuthRoutes(r *gin.Engine, db *data.Mongo, dbName string) {
	usersCol := db.DB(dbName).Collection("users")
	sessCol := db.DB(dbName).Collection("session")
	auth := r.Group("/auth") 

	auth.POST("/signup", handler.SignUp(usersCol))
	auth.POST("/signin", handler.SignIn(usersCol, sessCol))
}

// func authRoutes(r *gin.Engine) {
// 	auth := r.Group("/api/auth") 

// 	auth.POST("/login", handler.Login)
// 	auth.POST("/register", handler.Register)
// }