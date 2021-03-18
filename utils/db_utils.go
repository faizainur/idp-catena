package utils

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DbUtils struct {
	ConnectionString string
}

func (d *DbUtils) Connect(ctx context.Context) (*mongo.Client, error) {

	// Configure mongodb client options
	clientOptions := options.Client().ApplyURI(d.ConnectionString)

	// Connect to the mongodb
	client, err := mongo.Connect(ctx, clientOptions)

	return client, err
}
