package main

import (
	"base/auth"
	"base/controlers"
	"base/routes"
	"os"

	"base/models"

	"time"

	"base/initials"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func init() {

	initials.LoadEnvVariables()
	initials.Db()

	models.Migrate()

	// subscription.GenerateStripePaymentMethods() //for test
	println("success")
}

func main() {

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5000", "http://localhost:5175","https://conn-6sq5.onrender.com", "http://localhost:5173", "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:5175", "http://127.0.0.1:5178", "http://127.0.0.1:5176", "http://127.0.0.1:5177"}, // Frontend URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Requested-With", "X-XSRF-TOKEN", "Refresh-Token"},
		AllowCredentials: true, // Required for cookies & auth headers
		MaxAge:           12 * time.Hour,
	}))
	r.Static("/static", "./static")
	r.GET("/users/search", auth.LoginRequired, controlers.SearchUsers)

	auth.Routes(r)
	routes.Routes(r)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default to 8080 if PORT is not set
	}

	// Start the server on the dynamic port
	r.Run(":" + port) // Listen on the port provided by Render

}
