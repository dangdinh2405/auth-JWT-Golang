package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// type Session struct {
//     ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
//     UserID       primitive.ObjectID `bson:"userId" json:" userId"`
//     // DeviceID     string             `bson:"deviceId,omitempty"`
//     // UserAgent    string             `bson:"userAgent,omitempty"`
//     // IP           string             `bson:"ip,omitempty"`
//     RefreshTokenHash string         `bson:"refreshTokenHash" json:"refreshTokenHash"`
//     ExpiresAt    time.Time          `bson:"expiresAt" json:"expiresAt"`
//     CreatedAt    time.Time          `bson:"createdAt" json:"createdAt"`
//     UpdatedAt    time.Time          `bson:"updatedAt" json:"updatedAt"`
// }

type Session struct {
	RefreshToken string                `bson:"refreshToken" json:" refreshToken"`
	UserID       primitive.ObjectID    `bson:"userId" json:" userId"`     // hoặc primitive.ObjectID
	ExpiresAt    time.Time 			   `bson:"expiresAt" json:" expiresAt"`  // TTL index dựa trên field này
	CreatedAt    time.Time             `bson:"createdAt" json:" createdAt"`
	UpdatedAt    time.Time             `bson:"updatedAt" json:" updatedAt"`
}