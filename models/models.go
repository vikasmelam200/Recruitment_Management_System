package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name            string `json:"name"`
	Email           string `json:"email" gorm:"unique"`
	Address         string `json:"address"`
	UserType        string `json:"user_type"`
	PasswordHash    string `json:"password_hash"`
	ProfileHeadline string `json:"profile_headline"`
	Profile         Profile
}

type Profile struct {
	gorm.Model
	UserID     uint   `json:"user_id" gorm:"primaryKey"`
	ResumeFile string `json:"resume_file"`
	Skills     string `json:"skills"`
	Education  string `json:"education"`
	Experience string `json:"experience"`
	Name       string `json:"name"`
	Email      string `json:"email" gorm:"unique"`
	Phone      string `json:"phone"`
}

type Job struct {
	gorm.Model
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	PostedOn          time.Time `json:"posted_on"`
	TotalApplications int       `json:"total_applications"`
	CompanyName       string    `json:"company_name"`
	PostedByID        uint
	PostedBy          User `gorm:"foreignKey:PostedByID"`
}

type Application struct {
	gorm.Model
	JobID  uint   `json:"job_id"`  // Foreign key to Job
	UserID uint   `json:"user_id"` // Foreign key to User (applicant)
	Status string `json:"status"`  // Application status (e.g., "Pending", "Accepted", "Rejected")
}
