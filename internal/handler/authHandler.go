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
    "go.mongodb.org/mongo-driver/bson/primitive"
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

type Session struct {
    RefreshToken string             `bson:"refreshToken" json:"refreshToken"`
    UserID       primitive.ObjectID `bson:"userId" json:"userId"` 
    ExpiresAt    time.Time          `bson:"expiresAt" json:"expiresAt"`
    CreatedAt    time.Time          `bson:"createdAt" json:"createdAt"`
    UpdatedAt    time.Time          `bson:"updatedAt" json:" updatedAt"`
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
            CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
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
			UserID: user.ID.Hex(),
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
            UserID:       user.ID,
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


func SignOut(sessionCol *mongo.Collection) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("refreshToken")
		if err == nil && token != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = sessionCol.DeleteOne(ctx, bson.M{"refreshToken": token})

			// Xoá cookie (đặt MaxAge < 0 để trình duyệt huỷ)
			// Nếu backend và frontend deploy tách rời, bạn có thể cần SameSite=None và Secure=true.
			// Gin (>=1.7) hỗ trợ SetSameSite, nếu version bạn có hỗ trợ thì bật dòng dưới:
			// c.SetSameSite(http.SameSiteNoneMode)
            c.SetSameSite(http.SameSiteNoneMode)
		    secure := false

			c.SetCookie(
				"refreshToken",
				"",     // value nil
				-1,     // MaxAge < 0 => delete
				"/",    // path
				"",     // domain (để trống hoặc set domain cụ thể nếu cần)
				secure,   // secure
				true,   // httpOnly
			)
		}

		c.Status(http.StatusNoContent)
	}
}


func RefreshToken(sessionCol *mongo.Collection) gin.HandlerFunc {
    return func(c *gin.Context) {
        jwtSecret := os.Getenv("ACCESS_TOKEN_SECRET")
        token, err := c.Cookie("refreshToken")
        if err != nil || token == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"message": "Token không tồn tại."})
            return
        }

        // 2) Find session in DB
        ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
        defer cancel()

        var sess Session
        if err := sessionCol.FindOne(ctx, bson.M{"refreshToken": token}).Decode(&sess); err != nil {
            c.JSON(http.StatusForbidden, gin.H{"message": "Token không hợp lệ hoặc đã hết hạn"})
            return
        }

        // 3) Check expiration date
        if time.Now().After(sess.ExpiresAt) {
            // Xóa session hết hạn ngay lập tức (MongoDB TTL sẽ xóa sau nhưng có thể có độ trễ)
            sessionCol.DeleteOne(ctx, bson.M{"refreshToken": token})
            c.JSON(http.StatusForbidden, gin.H{"message": "Token đã hết hạn."})
            return
        }

        // 4) Create new access token
        claims := jwt.MapClaims{
            "uid": sess.UserID.Hex(),
            "exp": time.Now().Add(accessTTL).Unix(),
            "iat": time.Now().Unix(),
            "sub": sess.UserID.Hex(),
        }
        newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        accessToken, err := newToken.SignedString([]byte(jwtSecret))
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"message": "Lỗi hệ thống"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"accessToken": accessToken})
    }
}
