package models

import (
	// "strings"
	"time"

	// "go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)


type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username        string            `bson:"username" json:"username"`               // required, unique, trim, lowercase
	HashedPassword string             `bson:"hashedPassword" json:"-"`                // required (ẩn khi json)
	Email          string             `bson:"email" json:"email"`                     // required, unique, trim, lowercase
	DisplayName    string             `bson:"displayName" json:"displayName"`         // required, trim
	AvatarURL      *string            `bson:"avatarUrl,omitempty" json:"avatarUrl"`   // optional
	AvatarID       *string            `bson:"avatarId,omitempty" json:"avatarId"`     // optional (Cloudinary public_id)
	Bio            *string            `bson:"bio,omitempty" json:"bio"`               // optional, maxlength 500 -> validate ứng dụng
	Phone          *string            `bson:"phone,omitempty" json:"phone"`           // optional, unique khi tồn tại (sparse/partial)
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time          `bson:"updatedAt" json:"updatedAt"`
}

