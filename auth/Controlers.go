package auth

import (
	"base/initials"
	"base/methods"
	"base/models"
	"bytes"

	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Login(c *gin.Context) {
	var body struct {
		EmailorUname string `json:"user"`
		Password     string `json:"password"`
	}

	// Bind the incoming request body to the struct
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read body",
		})
		return
	}

	var user models.User

	// Query the user by email or username
	result := initials.DB.Where("email = ? OR username = ?", body.EmailorUname, body.EmailorUname).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user not found",
		})
		return
	}

	// Compare the hashed password with the provided password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid credentials",
		})
		return
	}

	// Generate JWT access token using the generateJWT function
	accessToken, err := generateJWT(user.ID, time.Hour*24) // 24-hour access token
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not generate access token",
		})
		return
	}

	// Generate JWT refresh token using the generateJWT function
	refreshToken, err := generateJWT(user.ID, 30*24*time.Hour) // 30-day refresh token
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not generate refresh token",
		})
		return
	}

	// Set the access token in an HTTP-only cookie (secure, if using HTTPS)
	c.SetCookie("access_token", accessToken, 3600*24, "/", "", true, true) // 24-hour access token

	// Set the refresh token in an HTTP-only cookie (secure, if using HTTPS)
	c.SetCookie("refresh_token", refreshToken, 3600*24*30, "/", "", true, true) // 30-day refresh token

	// Send the access token and refresh token in headers for non-browser apps or APIs
	c.Header("Authorization", "Bearer "+accessToken) // Send access token in Authorization header
	c.Header("Refresh-Token", refreshToken)          // Send refresh token in a separate header

	// Respond with a success message
	c.JSON(http.StatusOK, gin.H{
		"message":       "login successful",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
func UserUpdate(c *gin.Context) {
	// Extract user from context (after being authenticated)
	currentUser := GetUser(c)

	if c.Request.Method == "GET" {
		// Generate signed URL for the avatar if it exists
		var avatarURL *string
		if currentUser.Avatar != nil {
			signedURL, err := initials.GenerateSignedURL(*currentUser.Avatar)
			if err == nil {
				avatarURL = &signedURL
			}
		}

		// Send the user information as a response
		c.JSON(http.StatusOK, gin.H{
			"email":      currentUser.Email,
			"username":   currentUser.Username,
			"first_name": currentUser.FirstName,
			"last_name":  currentUser.LastName,
			"avatar_url": avatarURL,
		})
		return
	}

	if c.Request.Method == "POST" {
		// Declare body structure for the update
		var body struct {
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		}

		// Bind the incoming request body to the struct
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}

		// Check if the username already exists
		var existingUser models.User
		if body.Username != "" && body.Username != currentUser.Username {
			if err := initials.DB.Where("username = ?", body.Username).First(&existingUser).Error; err == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "username already exists"})
				return
			}
		}

		// Update only the fields that have been provided
		if body.Username != "" {
			currentUser.Username = body.Username
		}
		if body.FirstName != "" {
			currentUser.FirstName = body.FirstName
		}
		if body.LastName != "" {
			currentUser.LastName = body.LastName
		}

		// Process image upload only if a file is provided
		file, header, err := c.Request.FormFile("avatar")
		if err == nil && file != nil {
			defer file.Close()

			buf, err := methods.CompressImage(file, header.Header.Get("Content-Type"))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process image"})
				return
			}

			// Upload to Cloudflare R2
			objectKey := fmt.Sprintf("avatars/%d-%s", time.Now().Unix(), header.Filename)
			s3Client := initials.CreateR2Client()
			_, err = s3Client.PutObject(&s3.PutObjectInput{
				Bucket: aws.String("halcon"),
				Key:    aws.String(objectKey),
				Body:   bytes.NewReader(buf.Bytes()),
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload image"})
				return
			}

			// Generate public URL for the avatar
			url := fmt.Sprintf("%s/%s", os.Getenv("R2_PUBLIC_URL"), objectKey)
			currentUser.Avatar = &url
		}

		// Save updated user to the database
		if err := initials.DB.Save(currentUser).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
			return
		}

		// Generate signed URL for the updated avatar if available
		var signedAvatarURL *string
		if currentUser.Avatar != nil {
			signedURL, err := initials.GenerateSignedURL(*currentUser.Avatar)
			if err == nil {
				signedAvatarURL = &signedURL
			}
		}

		// Send success response
		c.JSON(http.StatusOK, gin.H{
			"message": "User information updated successfully",
			"user": gin.H{
				"username":   currentUser.Username,
				"first_name": currentUser.FirstName,
				"last_name":  currentUser.LastName,
				"avatar_url": signedAvatarURL,
			},
		})
		return
	}

	// Handle unsupported HTTP methods
	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
}
func DeleteUser(c *gin.Context) {
	// Extract user from context (after being authenticated)
	currentUser := GetUser(c)

	// Declare body structure to receive password input
	var body struct {
		Password string `json:"password"`
	}

	// Bind the incoming request body to the struct
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Compare the provided password with the stored hashed password
	err := bcrypt.CompareHashAndPassword([]byte(currentUser.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid password"})
		return
	}

	// Delete the user from the database
	if err := initials.DB.Delete(&currentUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}

	// Optionally, you can clear any session or authentication-related data here
	// For example, clearing cookies or revoking tokens

	// Send success response
	c.JSON(http.StatusOK, gin.H{
		"message": "models.User account deleted successfully",
	})
	Logout(c)
}

func RefreshToken(c *gin.Context) {
	// First, attempt to get the refresh token from the cookie
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		// If no refresh token in the cookie, check the Authorization header
		refreshToken = c.GetHeader("Refresh-Token")
		if refreshToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "refresh token not found in cookie or header",
			})
			return
		}
	}

	// Parse and validate the refresh token
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid refresh token",
		})
		return
	}

	// Extract user ID from the refresh token claims
	var userID string
	switch v := claims["sub"].(type) {
	case string:
		userID = v
	case float64:
		// Convert float64 to string if the user ID is stored as a number
		userID = fmt.Sprintf("%.0f", v)
	default:
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid user ID type in token",
		})
		return
	}

	// Generate new access token (expires in 1 hour)
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 1).Unix(), // New access token expires in 1 hour
	})

	// Sign the new access token
	newAccessTokenString, err := newAccessToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not generate new access token",
		})
		return
	}

	// Set the new access token in the cookie (secure, if using HTTPS)
	c.SetCookie("access_token", newAccessTokenString, 3600*1, "/", "", true, true)

	// Send the new access token in the Authorization header for non-browser apps
	c.Header("Authorization", "Bearer "+newAccessTokenString)

	// Respond with the new access token
	c.JSON(http.StatusOK, gin.H{
		"access_token": newAccessTokenString,
	})

}

func Logout(c *gin.Context) {
	// Remove the refresh token by setting the cookie expiration time to a past date
	c.SetCookie("access_token", "", -1, "/", "", true, true)  // Setting expiration to -1 will delete the cookie
	c.SetCookie("refresh_token", "", -1, "/", "", true, true) // Setting expiration to -1 will delete the cookie
	// Respond with a success message indicating the user has been logged out
	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}
func ChangePassword(c *gin.Context) {
	user := GetUser(c) // Get authenticated user

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	// Bind request body
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Check if current password is correct
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.CurrentPassword))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect current password"})
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash new password"})
		return
	}

	// Update password in the database
	user.Password = string(hashedPassword)
	initials.DB.Save(&user)

	c.JSON(http.StatusOK, gin.H{"message": "password changed successfully"})
}
func ForgotPassword(c *gin.Context) {
	var body struct {
		EmailOrUsername string `json:"user"`
	}

	// Bind request
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Find active user by email or username
	var user models.User
	if err := initials.DB.Where("(email = ? OR username = ?) AND deleted_at IS NULL", body.EmailOrUsername, body.EmailOrUsername).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found or is deleted"})
		return
	}

	// Generate reset token (valid for 15 minutes)
	resetToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	// Sign token
	resetTokenString, err := resetToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate reset token"})
		return
	}

	// Form a reset URL with the token
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", os.Getenv("SERVER_URL"), resetTokenString)

	// Check if email verification is enabled
	if os.Getenv("VERIFICATION") == "true" {
		// Send the reset URL via email (using Gomail)
		if err := sendPasswordResetEmail(user.Email, resetURL); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not send reset email"})
			return
		}

		// Send the URL as part of the response
		c.JSON(http.StatusOK, gin.H{
			"message":   "password reset token generated and email sent",
			"reset_url": resetURL,
		})
	} else {
		// If VERIFICATION is false, return only the reset token in the response
		c.JSON(http.StatusOK, gin.H{
			"message": "password reset token generated",
			"token":   resetTokenString,
		})
	}
}

func UpdatePassword(c *gin.Context) {
	var body struct {
		ResetToken  string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	// Bind request
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Parse and validate reset token
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(body.ResetToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired reset token"})
		return
	}

	// Extract user ID from token
	userID, ok := claims["sub"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token payload"})
		return
	}

	// Find user
	var user models.User
	if err := initials.DB.First(&user, uint(userID)).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash new password"})
		return
	}

	// Update password
	user.Password = string(hashedPassword)
	initials.DB.Save(&user)

	// Generate new JWT tokens for login
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(30 * 24 * time.Hour).Unix(),
	})

	// Sign tokens
	accessTokenString, _ := accessToken.SignedString([]byte(os.Getenv("SECRET")))
	refreshTokenString, _ := refreshToken.SignedString([]byte(os.Getenv("SECRET")))

	// Set refresh token in cookie
	c.SetCookie("Auth", refreshTokenString, 3600*24*30, "/", "", true, true)

	// Response
	c.JSON(http.StatusOK, gin.H{
		"message":       "password updated successfully",
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
	})
}
func VerifyEmail(c *gin.Context) {
	var body struct {
		VerificationToken string `json:"verification_token"`
		Password          string `json:"password,omitempty"`
	}

	// Bind the incoming request body to the struct
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Parse the verification token
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(body.VerificationToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired verification token"})
		return
	}

	// Check if the token has expired
	expiration, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(expiration) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "verification token has expired"})
		return
	}

	// Extract user ID from token
	userID, ok := claims["sub"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token payload"})
		return
	}

	// Find the user
	var user models.User
	if err := initials.DB.First(&user, uint(userID)).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	// Update verification status
	user.IsVerified = true

	// If a password is provided, hash and update it
	if body.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}
		user.Password = string(hashedPassword)
	}

	// Save the user record
	if err := initials.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user verification status"})
		return
	}

	// Generate access and refresh tokens
	accessToken, err := generateJWT(user.ID, time.Hour*24) // 24-hour access token
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate access token"})
		return
	}

	refreshToken, err := generateJWT(user.ID, 30*24*time.Hour) // 30-day refresh token
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate refresh token"})
		return
	}

	// Set tokens in HTTP-only cookies
	c.SetCookie("access_token", accessToken, 3600*24, "/", "", true, true)      // 24-hour access token
	c.SetCookie("refresh_token", refreshToken, 3600*24*30, "/", "", true, true) // 30-day refresh token

	// Send tokens in headers
	c.Header("Authorization", "Bearer "+accessToken)
	c.Header("Refresh-Token", refreshToken)

	// Respond with success
	c.JSON(http.StatusOK, gin.H{"message": "email verified successfully"})
}

func ResendVerificationToken(c *gin.Context) {
	// Fetch the authenticated user
	user := GetUser(c) // Get the user from the context (Assumes user is authenticated)
	if user == nil {
		return // If user is nil, GetUser already returned an unauthorized response
	}

	// Check if the user is already verified
	if user.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "models.User is already verified"})
		return
	}

	// Generate a new verification token (valid for 24 hours)
	verificationToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,                               // models.User ID is the subject
		"exp": time.Now().Add(24 * time.Hour).Unix(), // Token expiration (24 hours)
	})

	// Sign the verification token
	tokenString, err := verificationToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate verification token"})
		return
	}

	// Check if email verification is enabled
	if os.Getenv("VERIFICATION") == "true" {
		// Send the token via email
		if err := sendVerificationEmail(user.Email, tokenString); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
			return
		}

		// Success response
		c.JSON(http.StatusOK, gin.H{"message": "Verification token sent to email"})
	} else {
		// Return the token as JSON if email verification is not enabled
		c.JSON(http.StatusOK, gin.H{
			"message":            "Verification token generated",
			"verification_token": tokenString,
		})
	}
}

// GetVerifiedAndUnverifiedUsers retrieves verified and unverified users separately
func GetVerifiedAndUnverifiedUsers(c *gin.Context) {

	var users []models.User
	var verifiedUsers []models.User
	var unverifiedUsers []models.User

	// Fetch all users from the database
	if err := initials.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		return
	}

	// Iterate through users and use IsVerified method
	for _, user := range users {
		if user.IsVerified {
			verifiedUsers = append(verifiedUsers, user)
		} else {
			unverifiedUsers = append(unverifiedUsers, user)
		}
	}

	// Return response in JSON
	c.JSON(http.StatusOK, gin.H{
		"verified_users":   verifiedUsers,
		"unverified_users": unverifiedUsers,
	})
}
func Validate(c *gin.Context) {
	user := GetUser(c)

	var avatarURL string
	if user.Avatar != nil {
		// Extract object key from stored avatar URL
		parsedURL, err := url.Parse(*user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid avatar URL"})
			return
		}
		objectKey := parsedURL.Path[1:] // Remove leading '/' if necessary

		signedURL, err := initials.GenerateSignedURL(objectKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate signed URL"})
			return
		}
		avatarURL = signedURL
	}

	c.JSON(http.StatusOK, gin.H{
		"logged_in":  true,
		"id":         user.ID,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"username":   user.Username,
		"verified":   user.IsVerified,
		"avatar_url": avatarURL,
	})
}
func Signup(c *gin.Context) {
	var body struct {
		Email     string `json:"email" form:"email"`
		Username  string `json:"username" form:"username"`
		Password  string `json:"password" form:"password"`
		FirstName string `json:"first_name" form:"first_name"`
		LastName  string `json:"last_name" form:"last_name"`
	}

	// Parse form data
	if err := c.ShouldBind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to hash password"})
		return
	}

	// Initialize avatarURL to nil, will only be set if an image is uploaded
	var avatarURL *string

	// Process image upload only if a file is provided
	file, header, err := c.Request.FormFile("avatar")
	if err == nil && file != nil {
		defer file.Close()

		buf, err := methods.CompressImage(file, header.Header.Get("Content-Type"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process image"})
			return
		}

		// Upload to Cloudflare R2
		objectKey := fmt.Sprintf("avatars/%d-%s", time.Now().Unix(), header.Filename)
		s3Client := initials.CreateR2Client()
		_, err = s3Client.PutObject(&s3.PutObjectInput{
			Bucket: aws.String("halcon"),
			Key:    aws.String(objectKey),
			Body:   bytes.NewReader(buf.Bytes()),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload image"})
			return
		}

		// Generate avatar URL if image is uploaded
		url := fmt.Sprintf("%s/%s", os.Getenv("R2_PUBLIC_URL"), objectKey)
		avatarURL = &url
	}

	// Start a database transaction
	tx := initials.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start transaction"})
		return
	}

	// Check if user already exists with the given email
	var existingUser models.User
	err = tx.Where("email = ?", body.Email).First(&existingUser).Error
	if err == nil {
		// User exists, check if they are inactive
		if existingUser.Inactive {
			// Update user details
			existingUser.Username = body.Username
			existingUser.FirstName = body.FirstName
			existingUser.LastName = body.LastName
			existingUser.Password = string(hash)

			// Update avatar if a new one is uploaded
			if avatarURL != nil {
				existingUser.Avatar = avatarURL
			}

			// Save the updated user
			if err := tx.Save(&existingUser).Error; err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
				return
			}

			// Commit the transaction
			if err := tx.Commit().Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to commit transaction"})
				return
			}

			// Respond with success message
			c.JSON(http.StatusOK, gin.H{
				"message":    "User updated successfully",
				"avatar_url": avatarURL,
			})
			return
		} else {
			// User exists and is active, respond with an error
			tx.Rollback()
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists and is active"})
			return
		}
	} else if err == gorm.ErrRecordNotFound {
		// If no user is found, create a new user
		user := models.User{
			Email:     body.Email,
			Username:  body.Username,
			Password:  string(hash),
			FirstName: body.FirstName,
			LastName:  body.LastName,
			Avatar:    avatarURL,
		}

		if err := tx.Create(&user).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add user"})
			return
		}

		// Commit the transaction
		if err := tx.Commit().Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to commit transaction"})
			return
		}
		accessToken, err := generateJWT(user.ID, time.Hour*24) // 24-hour access token
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "could not generate access token",
			})
			return
		}

		// Generate JWT refresh token using the generateJWT function
		refreshToken, err := generateJWT(user.ID, 30*24*time.Hour) // 30-day refresh token
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "could not generate refresh token",
			})
			return
		}
		redirectURL := "https://conn-6sq5.onrender.com/login?access_token=" + accessToken + "&refresh_token=" + refreshToken
		c.Redirect(http.StatusFound, redirectURL)
		// Respond with success message
		c.JSON(http.StatusOK, gin.H{
			"message":    "User created successfully",
			"avatar_url": avatarURL,
		})
		return
	} else {
		// Database error while checking for existing user
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check if user exists"})
		return
	}
}

func CheckDuplicate(c *gin.Context) {
	// Define a struct to hold the incoming request data
	type RequestData struct {
		Email    string `json:"email"`
		Username string `json:"username"`
	}

	// Bind the JSON request body to the RequestData struct
	var body RequestData
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Initialize a response map to store the results for email and username
	response := gin.H{}

	// Check for email duplication (including soft-deleted users)
	if body.Email != "" {
		var existingUser models.User
		// Check for the email in active (non-deleted) users
		if err := initials.DB.Where("email = ? AND deleted_at IS NULL AND inactive = ?", body.Email, false).First(&existingUser).Error; err == nil {
			// Email already exists among active users
			response["email"] = true
		} else if err == gorm.ErrRecordNotFound {
			// Email does not exist among active users
			response["email"] = false
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check email duplication"})
			return
		}
	}

	// Check for username duplication (including soft-deleted users)
	if body.Username != "" {
		var existingUser models.User
		if err := initials.DB.Unscoped().Where("username = ?", body.Username).First(&existingUser).Error; err == nil {
			// Username already exists
			response["username"] = true
		} else if err == gorm.ErrRecordNotFound {
			// Username does not exist
			response["username"] = false
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check username duplication"})
			return
		}
	}

	// Return the response with the duplication status for email and username
	c.JSON(http.StatusOK, response)
}
