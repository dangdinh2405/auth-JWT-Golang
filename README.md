## JWT Auth Backend (Go + MongoDB)

# ✨ Features
Signup / Signin (BCrypt password hashing)
Access Token (short TTL) + Refresh Token (long TTL) with rotation
Logout (server-side revoke refresh tokens)
Protected routes via AuthRequired middleware
Token storage: stateless access (JWT)
Secure cookies (HttpOnly, Secure, SameSite=Strict/Lax)
Rate-limit ready & CORS-safe defaults

# 🧱 Tech Stack
Go 1.22+
Gin (github.com/gin-gonic/gin)
MongoDB Go Driver (go.mongodb.org/mongo-driver/mongo)
JWT (github.com/golang-jwt/jwt/v5)
BCrypt (golang.org/x/crypto/bcrypt)

# 🔐 Token Strategy
Access Token: TTL 15m (Bearer in Authorization header).
Refresh Token: TTL 7–30d, rotated on every refresh; stored in cookie (HttpOnly) + DB record with jti, userId, expiresAt.
Logout: delete the refresh record in DB (server-side revoke).
Compromise handling: if a used refresh token’s jti is not found (or already rotated), revoke all tokens for that user session.

# ⚙️ Environment
```
PORT = 
MONGO_CONECTION = ...
MONGO_DB_NAME = ...

ACCESS_TOKEN_SECRET = ...
```

# ▶️ Run Locally
```
go mod tidy
go run ./cmd/api
```

# 🔌 REST API
```
1) POST /auth/signup
Body
{
    "Username": "user2",
    "Password": "abc",
    "Email": "user1@gmail.com",
    "FirstName": "User",
    "LastName": "Một"
}
Status 204 No Content
```
```
2) POST /auth/signin
Body
{
    "Username": "user2",
    "Password": "abc"
}
Status 200 OK
```
```
3) POST /auth/signout
Body
{
}
Status 204 No Content
```
```
4) POST /auth/refresh
Body
{
}
Status 200 OK
```
```
4) GET /users/me
Body
{
}
Status 200 OK
```
