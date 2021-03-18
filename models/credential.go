package models

type Credential struct {
	UserUid         string `json:"userUid"  bson:"userUid"  form:"userUid"`
	Email           string `json:"email"  bson:"email"  form:"email"  binding:"required"`
	Password        string `json:"password,omitempty"  bson:"password"  form:"password"  binding:"required"`
	CreatedAt       string `json:"created_at,omitempty"  bson:"created_at"  form:"created_at"`
	UpdatedAt       string `json:"updated_at,omitempty"  bson:"updated_at"  form:"updated_at"`
	IsAdmin         bool   `json:"is_admin"  bson:"is_admin"  form:"is_admin"`
	CredentialType  string `json:"credential_type,omitempty"  bson:"credential_type"  form:"credential_type"`
	IsEmailVerified bool   `json:"is_email_verified"  bson:"is_email_verified"  form:"is_email_verified"`
}
