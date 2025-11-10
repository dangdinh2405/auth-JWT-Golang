package data

import (
	"context"
	"time"
    "log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Mongo struct {
	client *mongo.Client
}


func NewMongo(uri string) (*Mongo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := options.Client().
		ApplyURI(uri).
		SetMinPoolSize(5).               
		SetMaxPoolSize(50).               
		SetMaxConnIdleTime(60 * time.Second)

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
    log.Println("MongoDB connected")


	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	return &Mongo{client: client}, nil
}

// DB lấy database từ URI (vì bạn đã khai báo db trong URI)
func (m *Mongo) DB(name string) *mongo.Database {
	return m.client.Database(name)
}

// C lấy collection trực tiếp
func (m *Mongo) C(dbName, colName string) *mongo.Collection {
	return m.client.Database(dbName).Collection(colName)
}

// Close đóng kết nối khi tắt app (graceful shutdown)
func (m *Mongo) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.client.Disconnect(ctx)
}
