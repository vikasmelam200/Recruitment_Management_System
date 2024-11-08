package main

import (
	"Recruitment_Management_System/config"
	"Recruitment_Management_System/controllers"
	"Recruitment_Management_System/middlewares"

	"github.com/gin-gonic/gin"
)

func main() {
	config.ConnectDatabase()
	router := gin.Default()

	// Public routes (no authentication required)
	router.POST("/login", controllers.Login)
	router.POST("/signup", controllers.Signup)

	// Private routes (JWT authentication required)
	protected := router.Group("/")
	protected.Use(middlewares.AuthMiddleware())
	protected.POST("/uploadresume", controllers.UploadResume)
	protected.POST("/admin/job", controllers.CreateJob)
	protected.GET("/admin/job/:job_id", controllers.GetJobDetails)
	protected.GET("/admin/applicants", controllers.GetAllApplicants)
	protected.GET("/admin/applicant/:applicant_id", controllers.GetApplicantDetails)
	protected.GET("/jobs", controllers.GetJobs)
	protected.GET("/jobs/apply", controllers.ApplyForJob)
	protected.POST("/applicant/parse_resume", controllers.ParseResume)

	router.Run(":8080")
}
