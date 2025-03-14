package controlers

import (
	"base/auth"
	"base/initials"
	"base/methods"
	"base/models"
	"base/sockets"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

func RoomCreate(c *gin.Context) {
	// Get the authenticated user
	user := auth.GetUser(c)

	// Define the structure to bind the request body
	var body struct {
		RoomType        string   `json:"room_type" binding:"required"`
		RecipientEmails []string `json:"recipient_emails"` // Optional recipients for group/oneone
	}

	// Bind the incoming JSON body to the struct
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Check the room type and validate the room creation logic
	var roomType string
	switch strings.ToLower(body.RoomType) {
	case "oneone":
		roomType = "oneone"
		if len(body.RecipientEmails) != 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "oneone rooms must have exactly one recipient"})
			return
		}

		// Check if the recipient exists or create the user if not found
		recipientEmail := body.RecipientEmails[0]
		var recipient models.User
		err := initials.DB.Where("email = ?", recipientEmail).First(&recipient).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				// User doesn't exist, create new user
				username := recipientEmail
				newUser := models.User{
					Username: username,
					Email:    recipientEmail,
					Inactive: true, // Mark user as inactive initially
				}

				if err := initials.DB.Create(&newUser).Error; err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create recipient user"})
					return
				}

				recipient = newUser // Use the newly created user
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
				return
			}
		}

		// Query to check if there's an existing oneone room where both users are members
		var existingRoom models.Room
		err = initials.DB.Table("rooms r").
			Joins("JOIN room_users ru1 ON ru1.room_id = r.id").
			Joins("JOIN room_users ru2 ON ru2.room_id = r.id").
			Where("r.room_type = ? AND ru1.user_id = ? AND ru2.user_id = ?", "oneone", user.ID, recipient.ID).
			First(&existingRoom).Error

		if err == nil && existingRoom.ID != 0 {
			// If an existing room is found, return the existing room
			c.JSON(http.StatusOK, gin.H{
				"message": "One-on-one room already exists",
				"room":    existingRoom,
			})
			return
		} else if err != nil && err != gorm.ErrRecordNotFound {
			// Handle query error
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing rooms"})
			return
		}

	case "group":
		roomType = "group"
	case "public":
		roomType = "public"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid room type. Valid types are: oneone, group, public"})
		return
	}

	// Create the room object
	room := models.Room{
		RoomName: nil,
		RoomType: roomType,
		Users:    []models.User{*user},
	}

	// Save the room first to get its ID
	if err := initials.DB.Create(&room).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create room"})
		return
	}

	// Now update the user's RoomIDs with the correct room.ID
	if user.RoomIDs == nil {
		user.RoomIDs = pq.Int64Array{}
	}
	user.RoomIDs = append(user.RoomIDs, int64(room.ID))

	if err := initials.DB.Model(&user).Update("room_ids", user.RoomIDs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user's room IDs"})
		return
	}

	var roomUsers []models.RoomUser // For storing RoomUser associations
	// If room type is "oneone" or "group", resolve the recipient by email
	if roomType == "oneone" || roomType == "group" {
		recipientEmails := body.RecipientEmails
		var recipients []models.User

		// Add the creator to the room with the "admin" role
		roomUsers = append(roomUsers, models.RoomUser{
			RoomID:   room.ID,
			UserID:   user.ID,
			Role:     "admin", // Creator gets the admin role
			Accepted: true,    // Creator automatically accepts the invitation
			JoinedAt: time.Now(),
		})

		// Look up the users by their email and add them as members (or create them if not found)
		for _, email := range recipientEmails {
			var recipient models.User
			err := initials.DB.Where("email = ?", email).First(&recipient).Error
			if err != nil {
				if err == gorm.ErrRecordNotFound {
					// User doesn't exist, create new user
					username := email
					newUser := models.User{
						Username: username,
						Email:    email,
						Inactive: true, // Mark user as inactive initially
					}
					if err := initials.DB.Create(&newUser).Error; err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create recipient user"})
						return
					}
					if newUser.RoomIDs == nil {
						newUser.RoomIDs = pq.Int64Array{}
					}
					// Add room ID to the new user's RoomIDs field
					newUser.RoomIDs = append(newUser.RoomIDs, int64(room.ID))
					if err := initials.DB.Save(&newUser).Error; err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update recipient's room IDs"})
						return
					}

					// Add the new user to the recipients and their association as member
					recipients = append(recipients, newUser)
					roomUsers = append(roomUsers, models.RoomUser{
						RoomID:   room.ID,
						UserID:   newUser.ID,
						Role:     "member", // All other users are members
						Accepted: false,    // Set Accepted as false for members by default
						JoinedAt: time.Now(),
					})
				} else {
					// Database error
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
					return
				}
			} else {
				// User found, add them as a member to the room
				recipient.RoomIDs = append(recipient.RoomIDs, int64(room.ID))
				if err := initials.DB.Save(&recipient).Error; err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update recipient's room IDs"})
					return
				}
				recipients = append(recipients, recipient)

				// Add recipient to the room as a member
				roomUsers = append(roomUsers, models.RoomUser{
					RoomID:   room.ID,
					UserID:   recipient.ID,
					Role:     "member", // Assign them as a member
					Accepted: false,    // Set Accepted as false by default
					JoinedAt: time.Now(),
				})
			}
		}

		// Add recipients to the room's users list
		room.Users = append(room.Users, recipients...)
	}

	// Save the room-user associations to the RoomUser table
	for _, roomUser := range roomUsers {
		if err := initials.DB.Create(&roomUser).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign users to the room"})
			return
		}
	}

	// Update the room with the added users
	if err := initials.DB.Save(&room).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update room with users"})
		return
	}

	// Broadcast room update
	sockets.BroadcastRoomUpdate(room.ID, nil)

	// Respond with the newly created room details
	c.JSON(http.StatusOK, gin.H{
		"message": "Room created successfully",
		"room":    room,
	})
}

// CreateMessage handles creating a new message in a room

// CreateMessage handles message creation with text and file attachments
func CreateMessage(c *gin.Context) {
	// Extract sender from authentication
	sender := auth.GetUser(c)

	// Get room ID from the route
	roomID, err := strconv.ParseUint(c.Param("room_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid room ID"})
		return
	}

	// Parse form data
	var input struct {
		Content string `form:"content"`
	}
	if err := c.ShouldBind(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read message content"})
		return
	}

	// Determine message type
	messageType := "text"
	if input.Content == "" {
		messageType = "file" // If there's no text, assume it's a file message
	}

	// Create and save the message in the database
	message := models.Message{
		Content:     input.Content,
		SenderID:    sender.ID,
		RoomID:      uint(roomID),
		MessageType: messageType,
	}

	if err := initials.DB.Create(&message).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save message"})
		return
	}

	// Handle file uploads
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse form data"})
		return
	}

	files := form.File["files"] // Retrieve multiple files from form-data
	var attachments []models.Attachment
	s3Client := initials.CreateR2Client()

	for _, header := range files {
		// Open file
		file, err := header.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file"})
			return
		}
		defer file.Close()

		// Check file type
		fileType, err := detectFileType(header)
		if err != nil {
			continue // Skip unsupported file types
		}

		// Read file into buffer
		buf := new(bytes.Buffer)

		if fileType == "image" {
			// Compress image before uploading
			buf, err = methods.CompressImage(file, header.Header.Get("Content-Type"))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process image"})
				return
			}
		} else {
			_, err = io.Copy(buf, file) // Copy file data to buffer
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
				return
			}
		}

		// Upload file to R2
		objectKey := fmt.Sprintf("messages/%d-%s", time.Now().Unix(), header.Filename)
		_, err = s3Client.PutObject(&s3.PutObjectInput{
			Bucket: aws.String("halcon"),
			Key:    aws.String(objectKey),
			Body:   bytes.NewReader(buf.Bytes()),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file"})
			return
		}

		// Generate file URL
		fileURL := fmt.Sprintf("%s/%s", os.Getenv("R2_PUBLIC_URL"), objectKey)

		// Create attachment record with Name field
		attachment := models.Attachment{
			MessageID: message.ID,
			Type:      fileType,
			Link:      fileURL,
			Name:      header.Filename, // Save the original file name
		}
		attachments = append(attachments, attachment)
	}

	// Save attachments to database
	if len(attachments) > 0 {
		if err := initials.DB.Create(&attachments).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save attachments"})
			return
		}
		// Update message type if it contains files
		initials.DB.Model(&message).Update("MessageType", "file")
	}

	go sockets.BroadcastMessage(message.ID)
	sockets.BroadcastRoomUpdate(message.RoomID, &message)
	// Send success response
	c.JSON(http.StatusOK, gin.H{
		"message":     "Message sent successfully",
		"messageData": message,
		"attachments": attachments,
	})
}

// detectFileType determines whether the file is an image, general file, or an executable
func detectFileType(fileHeader *multipart.FileHeader) (string, error) {
	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))

	// Define allowed image extensions
	imageExtensions := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".webp": true,
	}

	// Define executable file extensions (block these)
	executableExtensions := map[string]bool{
		".exe": true, ".sh": true, ".bat": true, ".bin": true, ".app": true, ".cmd": true, ".com": true, ".msi": true,
	}

	// Reject executable files
	if executableExtensions[ext] {
		return "", fmt.Errorf("executable files are not allowed")
	}

	// Identify images
	if imageExtensions[ext] {
		return "image", nil
	}

	return "file", nil // Other file types (e.g., PDF, DOCX) are allowed
}
