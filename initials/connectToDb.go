package initials

import (
	"fmt"
	"os"
	"log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

)

var DB *gorm.DB

func Db() {
	var err error
	
	// Get the database URL from environment variables
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is not set")  // Ensure the variable is set
	}

	// Open a connection to the database using GORM and the PostgreSQL driver
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect to database:", err)
	}

	// Optionally, print a success message
	fmt.Println("Successfully connected to the database!")
}
