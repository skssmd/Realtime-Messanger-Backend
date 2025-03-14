package auth

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	oauth2v2 "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"gorm.io/gorm"

	"base/initials"
	"base/models"
)

var googleOAuthConfig = &oauth2.Config{
	ClientID:     "954038516049-7ruvuuttebgren43a5h7tvnt4en0vaqa.apps.googleusercontent.com",
	ClientSecret: "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",
	RedirectURL:  "https://connect-1naf.onrender.com/auth/google/callback",
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
	Endpoint:     google.Endpoint,
}

func GoogleLogin(c *gin.Context) {
	url := googleOAuthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code not found"})
		return
	}

	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println("Token exchange error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	client := googleOAuthConfig.Client(context.Background(), token)

	oauth2Service, err := oauth2v2.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Println("OAuth2 service creation failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create OAuth2 service"})
		return
	}

	userinfo, err := oauth2Service.Userinfo.Get().Do()
	if err != nil {
		log.Println("Failed to retrieve user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	names := strings.SplitN(userinfo.Name, " ", 2)
	firstName := names[0]
	lastName := ""
	if len(names) > 1 {
		lastName = names[1]
	}

	// Start a database transaction
	tx := initials.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start transaction"})
		return
	}

	// Check if user already exists with the given email
	var existingUser models.User
	err = tx.Where("email = ?", userinfo.Email).First(&existingUser).Error
	if err == nil {
		// User exists, update Google tokens
		existingUser.GoogleToken = &token.AccessToken
		existingUser.GoogleRefreshToken = &token.RefreshToken

		// Update user details if they are inactive
		if existingUser.Inactive {
			existingUser.Username = userinfo.Email
			existingUser.FirstName = firstName
			existingUser.LastName = lastName
			existingUser.Inactive = false
		}

		// Save the updated user
		if err := tx.Save(&existingUser).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}

		// Commit the transaction
		if err := tx.Commit().Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
			return
		}

		// Generate JWTs for existing user
		accessTokenJWT, err := generateJWT(existingUser.ID, time.Hour*24)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		refreshTokenJWT, err := generateJWT(existingUser.ID, time.Hour*24*30)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
			return
		}

		// Redirect to frontend with JWT tokens
		redirectURL := "https://conn-6sq5.onrender.com/login?access_token=" + accessTokenJWT + "&refresh_token=" + refreshTokenJWT
		c.Redirect(http.StatusFound, redirectURL)
		return

	} else if err == gorm.ErrRecordNotFound {
		// If no user is found, create a new user
		user := models.User{
			Email:              userinfo.Email,
			Username:           userinfo.Email,
			FirstName:          firstName,
			LastName:           lastName,
			GoogleToken:        &token.AccessToken,
			GoogleRefreshToken: &token.RefreshToken,
			IsVerified:         true,
		}

		if err := tx.Create(&user).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user"})
			return
		}

		// Commit the transaction
		if err := tx.Commit().Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
			return
		}

		// Generate JWTs for new user
		accessTokenJWT, err := generateJWT(user.ID, time.Hour*24)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		refreshTokenJWT, err := generateJWT(user.ID, time.Hour*24*30)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
			return
		}

		// Redirect to frontend with JWT tokens
		redirectURL := "https://conn-6sq5.onrender.com/login?access_token=" + accessTokenJWT + "&refresh_token=" + refreshTokenJWT
		c.Redirect(http.StatusFound, redirectURL)
		return

	} else {
		// Unexpected error
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unexpected error"})
		return
	}
}

func GoogleConnect(c *gin.Context) {
	_, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in"})
		return
	}

	url := googleOAuthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}
func GoogleConnectCallback(c *gin.Context) {
	// Get user ID from the session/context (ensure LoginRequired middleware sets this)
	userId, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in"})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code not found"})
		return
	}

	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println("Token exchange error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	client := googleOAuthConfig.Client(context.Background(), token)

	oauth2Service, err := oauth2v2.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Println("OAuth2 service creation failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create OAuth2 service"})
		return
	}

	userinfo, err := oauth2Service.Userinfo.Get().Do()
	if err != nil {
		log.Println("Failed to retrieve user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// Find the logged-in user
	var user models.User
	if err := initials.DB.First(&user, userId).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Link Google account to the existing user
	accessToken := token.AccessToken
	refreshToken := token.RefreshToken
	user.GoogleToken = &accessToken
	user.GoogleRefreshToken = &refreshToken
	user.Avatar = &userinfo.Picture

	if err := initials.DB.Save(&user).Error; err != nil {
		log.Println("Error saving user:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link Google account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Google account linked successfully"})
}
