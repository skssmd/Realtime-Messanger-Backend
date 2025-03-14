package routes

import (
	"base/auth"
	"base/controlers"
	"base/sockets"

	"github.com/gin-gonic/gin"
)

func Routes(r *gin.Engine) {
	// Parent route /messages
	mGroup := r.Group("/messages")
	{
		// Create a new room
		mGroup.POST("/rooms/create", auth.LoginRequired, controlers.RoomCreate)

		// WebSocket for real-time room updates (e.g., user status, new messages)
		mGroup.GET("/rooms/socket", sockets.RoomSocket)

		// Get all rooms of the authenticated user
		mGroup.GET("/rooms/", auth.LoginRequired, sockets.GetRooms)

		// Send a message to a room
		mGroup.POST("/send/:room_id", auth.LoginRequired, controlers.CreateMessage)

		// WebSocket for real-time message streaming in a room
		mGroup.GET("/:room_id/socket", sockets.MessageSocket)
	}

}
