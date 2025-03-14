package initials

import (
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func CreateR2Client() *s3.S3 {
	// Replace these values with your actual credentials.
	accessKey := "ec368ad155beacd6f9b842054cdb83cb"
	secretKey := "ca795b3b14ba08ab5222e7042f4ba5e6bf1d3cf75fba0bc3d9d176030bc6be54"
	// Cloudflare R2 endpoint for the European Union (EU)
	endpoint := "https://fe7921c4866f6bb776462ade176bbd49.r2.cloudflarestorage.com"

	// Use S3ForcePathStyle to ensure the client works with R2
	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String("auto"),
		Endpoint:         aws.String(endpoint),
		Credentials:      credentials.NewStaticCredentials(accessKey, secretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
	})
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	return s3.New(sess)
}

// generateSignedURL creates a signed URL valid for 1 hour
func GenerateSignedURL(objectKey string) (string, error) {
	s3Client := CreateR2Client()

	req, _ := s3Client.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String("halcon"), // Your Cloudflare R2 bucket name
		Key:    aws.String(objectKey),
	})

	// Set expiration time for the signed URL (1 hour)
	signedURL, err := req.Presign(1 * time.Hour)
	if err != nil {
		return "", err
	}

	return signedURL, nil
}
