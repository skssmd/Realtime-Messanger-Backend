package sockets

import (
	"base/initials"
	"base/methods"
	"base/models"
	"encoding/json" // Add this line for JSON functionality
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var messageUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Adjust this for production security
	},
}

var (
	roomClients   = make(map[uint]map[*websocket.Conn]*models.User) // roomID -> connections
	roomClientsMu sync.Mutex
)

// UserResponse struct for sending room users
type UserResponse struct {
	ID     uint   `json:"id"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
}

// MessageResponse struct for sending messages
type MessageResponse struct {
	ID          uint         `json:"id"`
	Content     string       `json:"content"`
	SenderID    uint         `json:"sender_id"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Attachments []Attachment `json:"attachments"`
}

// Attachment struct
type Attachment struct {
	Name string `json:"name"`
	ID   uint   `json:"id"`
	Type string `json:"type"`
	Link string `json:"link"`
}

// MessageSocket handles real-time messaging
// MessageSocket handles real-time messaging with pagination support
func MessageSocket(c *gin.Context) {
	// Upgrade HTTP to WebSocket
	conn, err := messageUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}
	defer conn.Close()
	fmt.Println(c.Query("token"))
	// Authenticate the user
	user := methods.AuthForSocket(c)
	if user == nil {
		log.Println("Unauthorized WebSocket access")
		conn.WriteJSON(gin.H{"error": "unauthorized"})
		return
	}

	// Get room ID from request
	roomID := c.Param("room_id")
	var roomIDUint uint
	if _, err := fmt.Sscanf(roomID, "%d", &roomIDUint); err != nil {
		log.Println("Invalid room ID:", roomID)
		conn.WriteJSON(gin.H{"error": "invalid room id"})
		return
	}

	// Register user to the room
	roomClientsMu.Lock()
	if _, exists := roomClients[roomIDUint]; !exists {
		roomClients[roomIDUint] = make(map[*websocket.Conn]*models.User)
	}
	roomClients[roomIDUint][conn] = user
	roomClientsMu.Unlock()

	// Send all users in the room
	sendRoomUsers(conn, roomIDUint)

	// Send the latest 200 messages or previous messages if requested
	sendMessages(conn, roomIDUint, 200, 0) // Default: first 200 messages

	// Keep connection open until client disconnects
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Connection closed:", err)
			break
		}

		// Handle pagination requests to fetch older messages
		var request map[string]interface{}
		if err := json.Unmarshal(message, &request); err == nil {
			// If the client requests older messages (e.g., scroll to top)
			if beforeID, ok := request["before_id"].(float64); ok {
				// Send previous messages before the given message ID
				sendMessages(conn, roomIDUint, 200, uint(beforeID))
			}
		}
	}

	// Remove user from the room on disconnect
	roomClientsMu.Lock()
	delete(roomClients[roomIDUint], conn)
	roomClientsMu.Unlock()
}

// Send messages to the user with pagination
func sendMessages(conn *websocket.Conn, roomID uint, limit int, beforeID uint) {
	var messages []models.Message
	query := initials.DB.Where("room_id = ? AND deleted_at IS NULL", roomID)

	// If beforeID is provided, fetch older messages (before the provided message ID)
	if beforeID > 0 {
		query = query.Where("id < ?", beforeID)
	}

	// Fetch messages with pagination
	if err := query.Order("created_at DESC").
		Preload("Attachments").
		Limit(limit).
		Find(&messages).Error; err != nil {
		log.Println("Failed to fetch messages:", err)
		conn.WriteJSON(gin.H{"error": "failed to load messages"})
		return
	}

	// Convert messages to MessageResponse format
	var messageResponses []MessageResponse
	for _, msg := range messages {
		messageResponses = append(messageResponses, MessageResponse{
			ID:          msg.ID,
			Content:     msg.Content,
			SenderID:    msg.SenderID,
			CreatedAt:   msg.CreatedAt,
			UpdatedAt:   msg.UpdatedAt,
			Attachments: formatAttachments(msg.Attachments),
		})
	}

	// Send messages to the client (messages will be ordered from newest to oldest)
	conn.WriteJSON(gin.H{"messages": messageResponses})
}

// Send all users in the room
func sendRoomUsers(conn *websocket.Conn, roomID uint) {
	var roomUsers []models.User

	// Fetch all users in the room
	err := initials.DB.Raw(`
	SELECT u.id, u.first_name, u.last_name, u.username, u.avatar 
	FROM users u 
	JOIN room_users ru ON u.id = ru.user_id 
	WHERE ru.room_id = ?
	`, roomID).Scan(&roomUsers).Error

	if err != nil {
		log.Println("Failed to fetch room users:", err)
		conn.WriteJSON(gin.H{"error": "failed to load users"})
		return
	}

	// Format user response
	var userResponses []UserResponse
	for _, u := range roomUsers {
		userName := u.Username
		if u.FirstName != "" || u.LastName != "" {
			userName = strings.TrimSpace(u.FirstName + " " + u.LastName)
		}

		userResponses = append(userResponses, UserResponse{
			ID:     u.ID,
			Name:   userName,
			Avatar: GenerateSignedAvatarURL(u.Avatar),
		})
	}

	// Send users to client
	conn.WriteJSON(gin.H{"users": userResponses})
}

func BroadcastMessage(messageID uint) {
	var message models.Message
	if err := initials.DB.
		Preload("Attachments").
		First(&message, messageID).Error; err != nil {
		log.Println("broadcastMessage: message not found", err)
		return
	}

	msgResponse := MessageResponse{
		ID:          message.ID,
		Content:     message.Content,
		SenderID:    message.SenderID,
		CreatedAt:   message.CreatedAt,
		UpdatedAt:   message.UpdatedAt,
		Attachments: formatAttachments(message.Attachments),
	}

	roomID := message.RoomID
	roomClientsMu.Lock()
	if clients, ok := roomClients[roomID]; ok {
		for clientConn := range clients {
			if err := clientConn.WriteJSON(msgResponse); err != nil {
				log.Println("Error broadcasting message:", err)
			}
		}
	}
	roomClientsMu.Unlock()
}

// Send previous messages to user
func sendPreviousMessages(conn *websocket.Conn, roomID uint) {
	var messages []models.Message
	if err := initials.DB.Where("room_id = ? AND deleted_at IS NULL", roomID).
		Order("created_at ASC").
		Preload("Attachments").
		Find(&messages).Error; err != nil {
		log.Println("Failed to fetch messages:", err)
		conn.WriteJSON(gin.H{"error": "failed to load messages"})
		return
	}

	// Convert messages to MessageResponse format
	var messageResponses []MessageResponse
	for _, msg := range messages {
		messageResponses = append(messageResponses, MessageResponse{
			ID:          msg.ID,
			Content:     msg.Content,
			SenderID:    msg.SenderID,
			CreatedAt:   msg.CreatedAt,
			UpdatedAt:   msg.UpdatedAt,
			Attachments: formatAttachments(msg.Attachments),
		})
	}

	// Send messages to the client
	conn.WriteJSON(gin.H{"messages": messageResponses})
}

// Handle new incoming messages
func handleNewMessage(roomID uint, user *models.User, msgData []byte) {
	// Create message in database
	message := models.Message{
		Content:   string(msgData),
		SenderID:  user.ID,
		RoomID:    roomID,
		CreatedAt: time.Now(),
	}

	if err := initials.DB.Create(&message).Error; err != nil {
		log.Println("Failed to save message:", err)
		return
	}

	// Prepare message response
	msgResponse := MessageResponse{
		ID:          message.ID,
		Content:     message.Content,
		SenderID:    user.ID,
		CreatedAt:   message.CreatedAt,
		UpdatedAt:   message.UpdatedAt,
		Attachments: []Attachment{},
	}

	// Broadcast message to all users in the room
	roomClientsMu.Lock()
	for clientConn := range roomClients[roomID] {
		clientConn.WriteJSON(msgResponse)
	}
	roomClientsMu.Unlock()
}

// Format attachments for response
func formatAttachments(attachments []models.Attachment) []Attachment {
	var response []Attachment
	for _, att := range attachments {
		response = append(response, Attachment{
			Name: att.Name,
			ID:   att.ID,
			Type: att.Type,
			Link: GenerateSignedAvatarURL(&att.Link),
		})
	}
	return response
}
