package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/faizainur/idp-catena/models"
	"github.com/faizainur/idp-catena/validator"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const (
	BasicUser string = "basic"
	BankUser  string = "bank"
)

type UserManagement struct {
	Collection *mongo.Collection
}

type UserManagementError struct {
	arg     string
	message string
}

func (e *UserManagementError) Error() string {
	return fmt.Sprintf("%s : %s", e.arg, e.message)
}

func (u *UserManagement) LoginHandler(ctx context.Context, email string, password string) (models.Credential, error) {
	var data models.Credential
	errorArg := "Login Handler"

	filter := bson.D{{"email", email}}

	errMongo := u.Collection.FindOne(ctx, filter).Decode(&data)
	if errMongo != nil {
		return models.Credential{}, &UserManagementError{errorArg, "Email is not registered"}
	}

	errBcrypt := bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(password))
	if errBcrypt != nil {
		return models.Credential{}, &UserManagementError{errorArg, "Wrong Password"}
	}
	return data, nil
}

func (u *UserManagement) RegisterHandler(ctx context.Context, email string, password string) (models.Credential, error) {
	var data models.Credential
	errorArg := "Register Handler"

	// Validate email
	if isValidEmail := validator.IsValidEmail(email); !isValidEmail {
		return models.Credential{}, &UserManagementError{errorArg, "Invalid email address"}
	}

	isEmailExist, err := u.IsEmailExist(email)
	if err != nil {
		log.Fatal(err.Error())
	}

	if isEmailExist {
		return models.Credential{}, &UserManagementError{errorArg, "Email Already Exist"}
	}

	// Hashing password
	unsalted := []byte(password)
	saltedPassword, _ := bcrypt.GenerateFromPassword(unsalted, bcrypt.DefaultCost)

	// Add addtional data
	userUid, _ := uuid.NewV4()
	data.UserUid = userUid.String()
	data.Email = email
	data.Password = string(saltedPassword)
	data.CreatedAt = time.Now().Format(time.RFC3339)
	data.CredentialType = BasicUser
	data.IsAdmin = false
	data.IsEmailVerified = false

	u.Collection.InsertOne(ctx, data)

	// Omit password from http response
	data.Password = ""

	return data, nil
}

func (u *UserManagement) IsEmailExist(email string) (bool, error) {
	var isExist bool = false

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Count().SetMaxTime(2 * time.Second)
	count, err := u.Collection.CountDocuments(ctx, bson.D{{"email", email}}, opts)

	if count > 0 && err == nil {
		isExist = true
	}

	return isExist, err
}

func (u *UserManagement) UpdatePasswordHandler(ctx context.Context, keyword string, password string) error {
	errorArg := "Update Password Handler"
	// filter := bson.D{
	// 	{"$or": [
	// 		{"user_uid", keyword},
	// 		{"email": keyword},
	// 	]},
	// }

	filter := bson.D{{
		"$or", []interface{}{
			bson.D{{"user_uid", keyword}},
			bson.D{{"email", keyword}},
		},
	}}

	saltedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	var updatedDocument bson.M
	err := u.Collection.FindOneAndUpdate(
		ctx,
		filter,
		bson.D{{"$set", bson.D{{"password", string(saltedPassword)}}}},
		options.FindOneAndUpdate().SetMaxTime(2*time.Second),
		options.FindOneAndUpdate().SetUpsert(false),
	).Decode(&updatedDocument)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &UserManagementError{errorArg, "No record found in database"}
		}
		log.Fatal(err.Error())
	}
	return nil
}
