package handler

import (
    "context"
    "crypto/rand"
	"encoding/hex"
    "net/http"
    "time"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"

	"github.com/dangdinh2405/auth-JWT-Golang/internal/models"
)

type SignUpRequest struct {
    Username  string `json:"username" binding:"required"`
    Password  string `json:"password" binding:"required"`
    Email     string `json:"email" binding:"required"`
    FirstName string `json:"firstName" binding:"required"`
    LastName  string `json:"lastName" binding:"required"`
}

type SignInRequest struct {
    Username  string `json:"username" binding:"required"` 
    Password  string `json:"password" binding:"required"`
}

type jwtClaims struct {
	UserID string `json:"userId"`
	jwt.RegisteredClaims
}
var accessTTL = 15 * time.Minute
var refreshTTL = 30 * 24 * time.Hour

func SignUp(userCollection *mongo.Collection) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req SignUpRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid data"})
            return
        }

        if req.Username == "" || req.Password == "" || req.Email == "" || req.FirstName == "" || req.LastName == "" {
            c.JSON(http.StatusBadRequest, gin.H{"message": "username, password, email, firstName, and lastName are required."})
            return
        }

        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        var existingUser models.User
        err := userCollection.FindOne(ctx, bson.M{"username": req.Username}).Decode(&existingUser)
        if err == nil {
            c.JSON(http.StatusConflict, gin.H{"message": "username already exists"})
            return
        }
        if err != mongo.ErrNoDocuments {
            c.JSON(http.StatusInternalServerError, gin.H{"message": "System error (mongose)"})
            return
        }

        // hash password
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"message": "Error encode password"})
            return
        }

        // tạo user
        newUser := models.User{
            Username:       req.Username,
            HashedPassword: string(hashedPassword),
            Email:          req.Email,
            DisplayName:    req.FirstName + " " + req.LastName,
        }

        _, err = userCollection.InsertOne(ctx, newUser)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"message": "System error"})
            return
        }

        c.Status(http.StatusNoContent)
    }
}

func SignIn(userCollection *mongo.Collection, sessionCollection *mongo.Collection) gin.HandlerFunc {
    return func(c *gin.Context) {
        jwtSecret := os.Getenv("ACCESS_TOKEN_SECRET")

        var req SignInRequest
        if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid data"})
			return
		}

        if req.Username == "" || req.Password == "" {
            c.JSON(http.StatusBadRequest, gin.H{"message": "username, password are required."})
            return
        }

        // Find user by username
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

        var user models.User
        if err := userCollection.FindOne(ctx, bson.M{"username": req.Username}).Decode(&user); err != nil {
			if err == mongo.ErrNoDocuments {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "Incorrect username or password"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"message": "System error (mongo)"})
			return
		}

        // Compare password
		if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Incorrect username or password"})
			return
		}

        // Create JWT access token
		claims := jwtClaims{
			UserID: user.Username,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTTL)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		accessToken, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "System error"})
			return
		}

        // Create refresh token (64 bytes -> hex)
        buf := make([]byte, 64)
		if _, err := rand.Read(buf); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Lỗi hệ thống"})
			return
		}
		refreshToken := hex.EncodeToString(buf)

        // Save session
        sess := models.Session{
			RefreshToken: refreshToken,
            UserID:       user.Username,
			ExpiresAt:    time.Now().Add(refreshTTL),
            CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		if _, err := sessionCollection.InsertOne(ctx, sess); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "System error (create session in mongose)"})
			return
		}

        // Set cookie ( notion HTTPS / SameSite )
        // In production behind HTTPS:
		//   c.SetSameSite(http.SameSiteNoneMode)
		//   secure := true
		// For localhost dev you may need secure=false and SameSite=Lax
		c.SetSameSite(http.SameSiteNoneMode)
		secure := false // set to false locally if not using HTTPS
		c.SetCookie(
			"refreshToken",
			refreshToken,
			int(refreshTTL.Seconds()),
			"/",
			"",      // domain ("" = current host). Set your domain when deploying.
			secure,  // secure
			true,    // httpOnly
		)

        c.JSON(http.StatusOK, gin.H{
			"message":     "User " + user.DisplayName + " đã logged in!",
			"accessToken": accessToken,
		})
    }
}