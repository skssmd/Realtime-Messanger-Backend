package auth

import (
	"github.com/gin-gonic/gin"
)

// Routes defines all authentication-related routes.
func Routes(r *gin.Engine) {
	// Parent route /auth
	authGroup := r.Group("/auth")
	{
		// Signup route

		// Login route
		authGroup.POST("/login", Login)

		// Logout route (removes the refresh token)
		authGroup.POST("/logout", Logout)

		// Refresh token route (to get a new access token using the refresh token)
		authGroup.POST("/refresh-token", RefreshToken)

		authGroup.POST("/change-password", LoginRequired, ChangePassword)
		authGroup.GET("/validate", LoginRequired, Validate)
		authGroup.POST("/forgot-password", ForgotPassword)
		authGroup.POST("/reset-password", UpdatePassword)
		authGroup.POST("/verify-email", VerifyEmail)
		authGroup.POST("/resend-verification-token", LoginRequired, ResendVerificationToken)
		authGroup.GET("/google/login", GoogleLogin)
		authGroup.GET("/google/callback", GoogleCallback)
		authGroup.GET("/google/connect", LoginRequired, GoogleConnect)
		authGroup.GET("/google/connect/callback", LoginRequired, GoogleConnectCallback)

		r.POST("auth/signup", Signup)
		r.POST("auth/checkDuplicate", CheckDuplicate)
	}
	userroutes := r.Group("/user", LoginRequired) // Apply LoginRequired middleware to the whole group
	{
		userroutes.GET("/update", UserUpdate)    // GET request to retrieve user info
		userroutes.POST("/update", UserUpdate)   // POST request to update user info
		userroutes.DELETE("/delete", DeleteUser) // DELETE request to delete user
	}

}
