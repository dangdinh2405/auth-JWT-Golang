package store

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func EnsureSessionIndexes(ctx context.Context, sessCol *mongo.Collection) error {
	ttl := int32(0)
	model := mongo.IndexModel{
		Keys:    map[string]int{"expiresAt": 1},
		Options: &options.IndexOptions{ExpireAfterSeconds: &ttl},
	}
	_, err := sessCol.Indexes().CreateOne(ctx, model)
	return err
}