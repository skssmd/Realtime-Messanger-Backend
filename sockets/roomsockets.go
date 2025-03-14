package sockets

import (
	"base/auth"
	"base/initials"
	"base/methods"
	"base/models"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Adjust this for production security
	},
}

// Map to store connected clients by room

var mu sync.Mutex

// Global map to store connection -> user mapping.
var connToUser = make(map[*websocket.Conn]*models.User)

// WebSocket upgrader

// Room response structure
type RoomResponse struct {
	RoomID        uint   `json:"room_id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	LastMessage   string `json:"last_message"`
	LastMessageID uint   `json:"last_message_id"`
	Seen          bool   `json:"seen"`
	Avatar        string `json:"avatar"`
}

func RoomSocket(c *gin.Context) {
	// Upgrade the connection
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}

	// Get the authenticated user
	user := methods.AuthForSocket(c)
	if user == nil {
		log.Println("Unauthorized access attempt")
		conn.WriteJSON(gin.H{"error": "unauthorized"})
		conn.Close()
		return
	}
	connToUser[conn] = user

	// Mark user as online in the database
	user.Status = "online"
	initials.DB.Model(&user).Where("id = ?", user.ID).Update("status", "online")
	log.Printf("User %d is now online\n", user.ID)

	// Fetch the rooms the user is part of
	var roomUsers []models.RoomUser
	if err := initials.DB.Where("user_id = ? ", user.ID).Find(&roomUsers).Error; err != nil {
		log.Println("Failed to fetch rooms:", err)
		conn.WriteJSON(gin.H{"error": "failed to fetch rooms"})
		conn.Close()
		return
	}

	// Extract room IDs from roomUsers
	roomIDs := make([]uint, len(roomUsers))
	for i, ru := range roomUsers {
		roomIDs[i] = ru.RoomID
	}
	log.Println("Fetched Room IDs:", roomIDs)

	// Fetch room details
	var rooms []models.Room
	if err := initials.DB.Where("id IN ?", roomIDs).Preload("Users").Find(&rooms).Error; err != nil {
		log.Println("Failed to fetch room details:", err)
		conn.WriteJSON(gin.H{"error": "failed to fetch room details"})
		conn.Close()
		return
	}

	// Prepare room response
	var roomResponses []RoomResponse

	for _, room := range rooms {
		roomName := getRoomName(user, room)

		// Determine the correct avatar
		var avatarURL string
		if room.RoomType == "oneone" {
			// Find the other user's avatar
			for _, u := range room.Users {
				if u.ID != user.ID && u.Avatar != nil {
					// **Directly using your initials.GenerateSignedURL()**
					avatarURL = GenerateSignedAvatarURL(u.Avatar)

					break
				}
			}
		} else if room.RoomType == "group" || room.RoomType == "public" {
			if room.Avatar != nil {
				// **Directly using your initials.GenerateSignedURL()**
				avatarURL = GenerateSignedAvatarURL(room.Avatar)

			}
		}

		// Fetch last message
		var lastMessage models.Message
		initials.DB.Where("room_id = ? AND deleted_at IS NULL", room.ID).
			Order("created_at DESC").First(&lastMessage)

		lastMessageText := lastMessage.Content
		if len(lastMessageText) > 50 {
			lastMessageText = lastMessageText[:50] + "..."
		}

		// Check if the user has seen the message
		seen := hasUserSeen(lastMessage.SeenBy, user.ID)

		// Append room response
		roomResponses = append(roomResponses, RoomResponse{
			RoomID:        room.ID,
			Name:          roomName,
			Type:          room.RoomType,
			LastMessage:   lastMessageText,
			LastMessageID: lastMessage.ID,
			Seen:          seen,
			Avatar:        avatarURL,
		})
	}

	// Send initial room data to client
	err = conn.WriteJSON(roomResponses)
	if err != nil {
		log.Println("Error sending room data to client:", err)
		conn.Close()
		return
	}

	// Listen for incoming messages
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Println("User disconnected:", err)
			break
		}
	}

	// Mark user as offline in the database on disconnect
	initials.DB.Model(&user).Where("id = ?", user.ID).Update("status", "offline")
	log.Printf("User %d is now offline\n", user.ID)

	// Remove from active connections
	delete(connToUser, conn)

	// Close WebSocket connection
	conn.Close()
}

// Check if a user has seen the message
func hasUserSeen(seenBy []uint, userID uint) bool {
	for _, id := range seenBy {
		if id == userID {
			return true
		}
	}
	return false
}

// Broadcast room update
func BroadcastRoomUpdate(roomID uint, lastMessage *models.Message) {
	// Fetch the latest room details with users
	var room models.Room
	if err := initials.DB.Preload("Users").Where("id = ? AND deleted_at IS NULL", roomID).First(&room).Error; err != nil {
		log.Println("Error fetching room details:", err)
		return
	}

	// Debug: Check if users are loaded
	fmt.Println("Fetched room with users:", len(room.Users))

	// Fetch only online users in this room
	var onlineUsers []models.User
	if err := initials.DB.Raw(`
		SELECT u.* FROM users u
		JOIN room_users ru ON ru.user_id = u.id
		WHERE ru.room_id = ? AND u.status = 'online'
	`, roomID).Scan(&onlineUsers).Error; err != nil {
		log.Println("Error fetching online users:", err)
		return
	}

	if len(onlineUsers) == 0 {
		fmt.Println("No online users in this room.")
		return
	}

	fmt.Println("Number of online users in room:", len(onlineUsers))

	// Generate signed URL for the room avatar
	var roomAvatarURL string
	if room.Avatar != nil {
		roomAvatarURL = GenerateSignedAvatarURL(room.Avatar)
	}

	// Iterate over each online user and send updates
	for _, user := range onlineUsers {
		updatedName := getRoomName(&user, room)

		// Determine avatar
		var avatarURL string
		if room.RoomType == "oneone" {
			for _, u := range room.Users {
				if u.ID != user.ID {
					if u.Avatar != nil {
						parsedURL, err := url.Parse(*u.Avatar)
						if err == nil {
							objectKey := parsedURL.Path[1:]
							if signedURL, err := initials.GenerateSignedURL(objectKey); err == nil {
								avatarURL = signedURL
							}
						}
					}
					break
				}
			}
		} else {
			avatarURL = roomAvatarURL
		}

		// Prepare the update payload
		update := gin.H{
			"event":           "room_update",
			"room_id":         roomID,
			"name":            updatedName,
			"type":            room.RoomType,
			"last_message":    "",
			"last_message_id": nil,
			"seen":            false,
			"avatar":          avatarURL,
		}

		// Include last message if available
		if lastMessage != nil {
			update["last_message"] = lastMessage.Content
			update["last_message_id"] = lastMessage.ID
		}

		// Send update
		if err := SendUpdateToUser(user.ID, update); err != nil {
			log.Println("Error sending update to user:", err)
			continue
		}

		fmt.Println("Successfully sent update to user.")
	}
}

func GenerateSignedAvatarURL(avatarURL *string) string {
	if avatarURL == nil {
		return ""
	}

	parsedURL, err := url.Parse(*avatarURL)
	if err != nil {
		return ""
	}

	objectKey := parsedURL.Path[1:]
	signedURL, err := initials.GenerateSignedURL(objectKey)
	if err != nil {
		return ""
	}

	return signedURL
}

func SendUpdateToUser(userID uint, update gin.H) error {
	mu.Lock()
	defer mu.Unlock()

	// Iterate through active WebSocket connections to find the user
	for conn, user := range connToUser {
		if user.ID == userID {
			// Send the update via WebSocket
			err := conn.WriteJSON(update)
			if err != nil {
				log.Println("Error sending update to user:", err)
				conn.Close() // Close the connection if sending fails
				delete(connToUser, conn)
				return err
			}
			return nil // Successfully sent update
		}
	}

	// User is not connected
	return fmt.Errorf("user %d is not connected", userID)
}

// Generate room name
func getRoomName(user *models.User, room models.Room) string {
	fmt.Println(room.Users)
	trimUsername := func(username string) string {
		if strings.Contains(username, "@") {
			return strings.Split(username, "@")[0]
		}
		return username
	}

	// Debugging
	fmt.Println("Room type from getRoomName:", room.RoomType)

	// Handle one-on-one room
	if room.RoomType == "oneone" {
		fmt.Println("has oneone")
		for _, u := range room.Users {
			fmt.Println("has oneone")
			if u.ID != user.ID {
				// Debugging
				fmt.Println("One-on-one user:", u.ID, "FirstName:", u.FirstName, "LastName:", u.LastName, "Username:", u.Username)
				if u.FirstName != "" && u.LastName != "" {
					return fmt.Sprintf("%s %s", u.FirstName, u.LastName)
				}
				return trimUsername(u.Username)
			}
		}
	}

	// Handle group room
	if room.RoomType == "group" {
		// Debugging
		fmt.Println("Group room name (before checking nil):", room.RoomName)
		if room.RoomName != nil {
			return *room.RoomName
		}

		uniqueUsernames := make(map[string]bool)
		usernames := []string{}

		for _, u := range room.Users {
			if u.ID != user.ID {
				var name string
				if u.FirstName != "" {
					name = u.FirstName
				} else {
					name = trimUsername(u.Username)
				}

				// Debugging
				fmt.Println("Adding username:", name)

				if !uniqueUsernames[name] {
					uniqueUsernames[name] = true
					usernames = append(usernames, name)
				}
			}
		}

		userCount := len(usernames)
		if userCount > 2 {
			return fmt.Sprintf("%s, %s +%d", usernames[0], usernames[1], userCount-2)
		}
		return strings.Join(usernames, ", ")
	}

	// Default room name
	if room.RoomName != nil {
		return *room.RoomName
	}
	return "Unnamed Room"
}

func GetRooms(c *gin.Context) {
	// Get authenticated user
	user := auth.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Fetch rooms the user is part of
	var roomUsers []models.RoomUser
	if err := initials.DB.Where("user_id = ? AND accepted = true", user.ID).Find(&roomUsers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch rooms"})
		return
	}

	// Extract room IDs
	roomIDs := make([]uint, len(roomUsers))
	for i, ru := range roomUsers {
		roomIDs[i] = ru.RoomID
	}

	// Fetch room details
	var rooms []models.Room
	if err := initials.DB.Where("id IN ?", roomIDs).Preload("Users").Find(&rooms).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch room details"})
		return
	}

	// Prepare response
	var roomResponses []RoomResponse
	for _, room := range rooms {
		roomName := getRoomName(user, room)

		// Fetch last message (ignoring deleted messages)
		var lastMessage models.Message
		initials.DB.Where("room_id = ? AND deleted_at IS NULL", room.ID).
			Order("created_at DESC").First(&lastMessage)

		// Format last message text
		lastMessageText := lastMessage.Content
		if len(lastMessageText) > 50 {
			lastMessageText = lastMessageText[:50] + "..."
		}

		// Check if user has seen the last message
		seen := hasUserSeen(lastMessage.SeenBy, user.ID)

		// Append response
		roomResponses = append(roomResponses, RoomResponse{
			RoomID:        room.ID,
			Name:          roomName,
			LastMessage:   lastMessageText,
			LastMessageID: lastMessage.ID,
			Seen:          seen,
		})
	}

	// Return JSON response
	c.JSON(http.StatusOK, roomResponses)
}
