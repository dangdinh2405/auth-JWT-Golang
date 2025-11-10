package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// UserContext là type chung để lưu thông tin user trong context
type UserContext struct {
	ID          primitive.ObjectID `bson:"_id" json:"id"`
	Username    string             `bson:"username" json:"username"`
	Email       string             `bson:"email" json:"email"`
	DisplayName string             `bson:"displayName" json:"displayName"`
	CreatedAt      time.Time       `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time       `bson:"updatedAt" json:"updatedAt"`
}

func RequireAuth(userCol *mongo.Collection) gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtSecret := os.Getenv("ACCESS_TOKEN_SECRET")
		// Lấy Authorization Header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Access token not found"})
			c.Abort()
			return
		}

		// Tách token khỏi chuỗi "Bearer <token>"
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Giải mã + xác minh token
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusForbidden, gin.H{"message": "Access token expired or incorrect"})
			c.Abort()
			return
		}

		// Lấy claims (userId) từ token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid Token"})
			c.Abort()
			return
		}

		userId, ok := claims["userId"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "UserId not found in token"})
			c.Abort()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user UserContext

		userObjectID, err := primitive.ObjectIDFromHex(userId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user id"})
			c.Abort()
			return
		}

		err = userCol.FindOne(ctx, bson.M{"_id": userObjectID}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "User does not exist"})
			c.Abort()
			return
		}

		c.Set("user", user)

		c.Next() 
	}
}
