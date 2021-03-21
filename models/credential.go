package models

type Credential struct {
	UserUid         string `json:"user_uid,omitempty" bson:"user_uid" form:"user_uid"  bson:"user_uid"  form:"user_uid"  binding:"user_uid"`
	Email           string `json:"email,omitempty" bson:"email" form:"email" binding:"required"  bson:"email"  form:"email"  binding:"email"`
	Password        string `json:"password,omitempty" bson:"password" form:"password" binding:"required"  bson:"password"  form:"password"  binding:"password"`
	CreatedAt       string `json:"created_at,omitempty" bson:"created_at" form:"created_at"  bson:"created_at"  form:"created_at"  binding:"created_at"`
	UpdatedAt       string `json:"updated_at,omitempty" bson:"updated_at" form:"updated_at"  bson:"updated_at"  form:"updated_at"  binding:"updated_at"`
	IsAdmin         bool   `json:"is_admin,omitempty" bson:"is_admin" form:"is_admin"  bson:"is_admin"  form:"is_admin"  binding:"is_admin"`
	CredentialType  string `json:"credential_type,omitempty" bson:"credential_type" form:"credential_type"  bson:"credential_type"  form:"credential_type"  binding:"credential_type"`
	IsEmailVerified bool   `json:"is_email_verified,omitempty" bson:"is_email_verified" form:"is_email_verified"  bson:"is_email_verified"  form:"is_email_verified"  binding:"is_email_verified"`
	RefreshToken    string `json:"refresh_token,omitempty"  bson:"refresh_token"  form:"refresh_token"  binding:"refresh_token"`
}

/*
func (c *Credential) MarshalBinary() ([]byte, error) {

}
*/
