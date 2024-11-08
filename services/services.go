package services

import (
	"Recruitment_Management_System/config"
	"Recruitment_Management_System/models"

	"golang.org/x/crypto/bcrypt"
)

// --------------------------------Generated the hashed_password is here ----------------------------------------
//---------------------------------------------------------------------------------------------------------------
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CreateUser(user models.User) (*models.User, error) {

	passwordHash, err := HashPassword(user.PasswordHash)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = passwordHash
	result := config.DB.Create(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}
