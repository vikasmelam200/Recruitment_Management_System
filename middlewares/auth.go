package middlewares

import (
	"Recruitment_Management_System/controllers"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization"})
			c.Abort()
			return
		}
		tokenString = tokenString[len("Bearer "):]
		claims := &controllers.Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) { return controllers.JwtKey, nil })
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or Expired Token"})
			c.Abort()
			return
		}
		userType := "Applicant"
		c.Set("user_type", userType)
		userTypes := "Admin"
		c.Set("user_types", userTypes)
		c.Next()
	}
}
