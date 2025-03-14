package auth

import (
	"base/initials"
	"base/models"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
)

func LoginRequired(c *gin.Context) {
	// Try to get the access token from the cookie
	accessToken, err := c.Cookie("access_token")
	if err != nil {
		// If no access token in cookie, check the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication token missing"})
			c.Abort()
			return
		}

		// Extract the token from the 'Bearer <token>' format
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
			c.Abort()
			return
		}
		accessToken = authHeader[7:] // Extract the token part
	}

	// Parse and validate the access token
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid access token",
		})
		c.Abort()
		return
	}

	// Extract user ID from the access token claims
	var userID string
	switch v := claims["sub"].(type) {
	case string:
		// If the user ID is stored as a string, directly assign it
		userID = v
	case float64:
		// If the user ID is stored as a number (float64), convert it to string
		userID = fmt.Sprintf("%.0f", v)
	default:
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid user ID type in token",
		})
		c.Abort()
		return
	}

	// Fetch user from the database
	var user models.User
	if err := initials.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "user not found",
		})
		c.Abort()
		return
	}

	// Convert RoomIDs from []uint to pq.Int64Array
	var roomIDs pq.Int64Array
	for _, id := range user.RoomIDs {
		roomIDs = append(roomIDs, int64(id))
	}

	// Assign the converted array back to the user struct
	user.RoomIDs = roomIDs

	// Attach the user to the context for further use in handlers
	c.Set("user", &user)

	// Proceed with the request
	c.Next()
}

func RequireVerification(c *gin.Context) {

	if !GetUser(c).IsVerified {

		c.JSON(http.StatusForbidden, gin.H{"error": "user is not verified"})
		c.Abort()
		return // `IsVerified` already handles response & abort
	}
	c.Next() // Proceed if user is verified
}
