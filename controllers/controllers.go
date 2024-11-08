package controllers

import (
	"Recruitment_Management_System/config"
	"Recruitment_Management_System/models"
	"Recruitment_Management_System/services"
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var JwtKey = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
	Username string `json:"username"`
	UserType string `json:"user_type"`
	jwt.StandardClaims
}

// -----------------------------------user signup function is here ---------------------------------------
// -------------------------------------------------------------------------------------------------------
func Signup(c *gin.Context) {
	var user models.User

	// Bind JSON data from the request body to the SignupRequest struct
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Validate user input (for example, ensure email is provided)
	if user.Name == "" || user.Email == "" || user.PasswordHash == "" || user.UserType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields"})
		return
	}

	// Call service to create a user
	Createduser, err := services.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Respond with a success message and created user info (without password hash)
	c.JSON(http.StatusOK, gin.H{"message": "User created successfully", "user": Createduser})
}

// -----------------------------------user login function is here ----------------------------------------
// -------------------------------------------------------------------------------------------------------
func Login(c *gin.Context) {

	type LoginRequest struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	var user LoginRequest

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var storedUser models.User

	err := config.DB.Where("email = ?", user.Email).First(&storedUser).Error
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials..."})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.PasswordHash), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials--"})
		return
	}
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// -----------------------------------user upload-resume-function function is here ---------------------------------------
// -----------------------------------------------------------------------------------------------------------------------
func UploadResume(c *gin.Context) {
	userType, exists := c.Get("user_type")
	if !exists || userType != "Applicant" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only applicants can upload resumes."})
		return
	}

	file, err := c.FormFile("resume")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is required"})
		return
	}

	// Check file type (allow only PDF and DOCX)
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".pdf" && ext != ".docx" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only PDF and DOCX files are allowed"})
		return
	}

	// Save the file
	uploadPath := "./uploads/resumes/" + file.Filename
	if err := c.SaveUploadedFile(file, uploadPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Resume uploaded successfully"})
}

// -----------------------------------user createjob function function is here -------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------
func CreateJob(c *gin.Context) {
	userType, exists := c.Get("user_type")
	if !exists || userType != "Admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can create job openings."})
		return
	}

	var job models.Job
	if err := c.ShouldBindJSON(&job); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input data"})
		return
	}

	if err := config.DB.Create(&job).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create job"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Job created successfully", "job": job})
}

// -----------------------------------GetJobDetails function function is here --------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------
func GetJobDetails(c *gin.Context) {

	type Applicant struct {
		ID         uint   `json:"id"`
		Name       string `json:"name"`
		Email      string `json:"email"`
		Skills     string `json:"skills"`
		Experience string `json:"experience"`
	}

	type JobDetailsResponse struct {
		Title       string      `json:"title"`
		Description string      `json:"description"`
		PostedOn    time.Time   `json:"posted_on"`
		CompanyName string      `json:"company_name"`
		Applicants  []Applicant `json:"applicants"`
	}

	userType, exists := c.Get("user_type")
	if !exists || userType != "Admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can view job details."})
		return
	}

	jobID := c.Param("job_id")

	var job JobDetailsResponse
	if err := config.DB.Preload("Applicants").Where("id = ?", jobID).First(&job).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"job": job,
	})
}

// -----------------------------------GetAllApplications function function is here -------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------
func GetAllApplicants(c *gin.Context) {
	userType, exists := c.Get("user_type")
	if !exists || userType != "Admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only Admins can access this endpoint."})
		return
	}

	var users []models.User
	if err := config.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// -----------------------------------GetAllApplicaDetails function function is here -------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------
func GetApplicantDetails(c *gin.Context) {

	userType, exists := c.Get("user_type")
	if !exists || userType != "Admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only Admins can access this endpoint."})
		return
	}

	applicantID, err := strconv.Atoi(c.Param("applicant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid applicant ID"})
		return
	}

	var applicant models.User
	if err := config.DB.Preload("Profile").First(&applicant, applicantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Applicant not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"applicant": applicant})
}

// -----------------------------------GetAllApplicaDetails function function is here -------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------
func GetJobs(c *gin.Context) {

	var jobs []models.Job
	if err := config.DB.Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve job openings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

func ApplyForJob(c *gin.Context) {

	userType, exists := c.Get("user_type")
	if !exists || userType != "Applicant" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only applicants can apply for jobs"})
		return
	}

	jobIDStr := c.Query("job_id")
	if jobIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Job ID is required"})
		return
	}

	jobID, err := strconv.ParseUint(jobIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID format"})
		return
	}

	userID := c.GetUint("user_id")

	application := models.Application{
		JobID:  uint(jobID),
		UserID: userID,
		Status: "Pending",
	}

	if err := config.DB.Create(&application).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to apply for job"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully applied for the job"})
}

// -----------------------------------ParseResume function function is here -------------------------------------------
// --------------------------------------------------------------------------------------------------------------------
func ParseResume(c *gin.Context) {
	const apiURL = "https://api.apilayer.com/resume_parser/upload"
	const apiKey = "0bWeisRWoLj3UdXt3MXMSMWptYFIpQfS"
	userType, exists := c.Get("user_type")
	if !exists || userType != "Applicant" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only applicants can parse resumes."})
		return
	}

	// Retrieve file
	file, err := c.FormFile("resume")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Resume file is required"})
		return
	}

	// Open the file
	fileData, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not open the resume file"})
		return
	}
	defer fileData.Close()

	// Prepare the file for the request
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create form file"})
		return
	}
	_, err = io.Copy(part, fileData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not copy file data"})
		return
	}
	writer.Close()

	// Create the request to the Apilayer API
	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create request"})
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("apikey", apiKey)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send request to resume parser API"})
		return
	}
	defer resp.Body.Close()

	// Read the response
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response from resume parser API"})
		return
	}

	// Check if API returned an error status
	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Resume parser API returned an error", "details": string(responseData)})
		return
	}

	// Send parsed response back to client
	c.JSON(http.StatusOK, gin.H{"parsed_data": string(responseData)})
}
