package methods

import (
	"fmt"

	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gopkg.in/gomail.v2"
)

// GenerateJWT - Generates a JWT for the user
func GenerateJWT(userID uint, tokenexpiry time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(tokenexpiry).Unix(), // Token expires in 24 hours
	})

	return token.SignedString([]byte(os.Getenv("SECRET")))
}

// Function to send verification email
func SendVerificationEmail(toEmail, verificationURL string) error {
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", os.Getenv("EMAIL_FROM"))
	mailer.SetHeader("To", toEmail)
	mailer.SetHeader("Subject", "Email Verification")
	mailer.SetBody("text/plain", fmt.Sprintf("Please verify your email by clicking the following link:\n\n%s", verificationURL))

	dialer := gomail.NewDialer(
		os.Getenv("SMTP_SERVER"),
		587, // Port number for SMTP server
		os.Getenv("SMTP_USER"),
		os.Getenv("SMTP_PASSWORD"),
	)

	if err := dialer.DialAndSend(mailer); err != nil {
		return err
	}

	return nil
}
