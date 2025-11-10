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
	auth.POST("/signout", handler.SignOut(sessCol))
	auth.POST("/refresh", handler.RefreshToken(sessCol))
}

func UserRoutes(r *gin.Engine) {
	user := r.Group("/users") 

	user.GET("/me", handler.AuthMe())
}