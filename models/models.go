package models

import (
	"base/initials"
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type User struct {
	ID                 uint   `gorm:"primaryKey"`
	Username           string `gorm:"unique"`
	Email              string `gorm:"uniqueIndex:idx_active_email,where:deleted_at IS NULL;not null"`
	Password           string
	FirstName          string `gorm:"default:null"`
	LastName           string `gorm:"default:null"`
	IsVerified         bool   `gorm:"default:false"`
	Inactive           bool   `gorm:"default:false"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          gorm.DeletedAt `gorm:"index"`
	Avatar             *string        `gorm:"default:NULL"`
	EmailNotifications bool           `gorm:"default:true"`

	// Google Authentication
	GoogleID           *string `gorm:"uniqueIndex;default:NULL"`
	GoogleToken        *string `gorm:"default:NULL"`
	GoogleRefreshToken *string `gorm:"default:NULL"`

	// New fields for handling status and room memberships
	RoomIDs pq.Int64Array `gorm:"type:integer[]" json:"room_ids"` // for tracking the rooms user is part of
	Status  string        `gorm:"default:'offline'"`
}

// Optionally, you can add an enum for Status and Role in the database

type Room struct {
	ID            uint    `gorm:"primaryKey"`
	RoomName      *string `gorm:"type:string;null"`
	RoomType      string  `gorm:"type:string"` // Room type (e.g., "private", "group")
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`
	LastMessageID uint           `gorm:"index"` // Foreign key to the last message in the room
	Avatar        *string        `gorm:"default:NULL"`
	// Many-to-many relationship with User
	Users []User `gorm:"many2many:room_users;"`
}

// Many-to-many relation (through an intermediate table for memberships)
type RoomUser struct {
	RoomID   uint
	UserID   uint
	Role     string    `gorm:"default:'member'"` // 'member' by default
	Accepted bool      // False by default, to signify unaccepted invitation
	JoinedAt time.Time `gorm:"default:current_timestamp"`
}

type Message struct {
	ID          uint   `gorm:"primaryKey"`
	Content     string `gorm:"type:text"`
	SenderID    uint   `gorm:"not null"`
	RoomID      uint   `gorm:"not null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
	DeleveredTo []uint         `gorm:"type:jsonb"`
	SeenBy      []uint         `gorm:"type:jsonb"` // JSON array of user IDs who have seen the message

	Attachments []Attachment `gorm:"foreignKey:MessageID"` // Relation to Attachments (for media)

	// New field to track message type (text, image, file, etc.)
	MessageType string `gorm:"default:'text'"` // Type of message (text, image, etc.)
}

// Optionally, you can add more status types for future enhancements

// Attachment model
type Attachment struct {
	ID        uint   `gorm:"primaryKey"`
	MessageID uint   `gorm:"not null"`          // Foreign key to Message model
	Type      string `gorm:"type:varchar(255)"` // Type of the attachment (e.g., 'image', 'pdf', etc.)
	Name      string `gorm:"type:varchar(255)"` // Name of the attachment file
	Link      string `gorm:"type:varchar(255)"` // Link to the attachment file
	CreatedAt time.Time
	UpdatedAt time.Time
}

func Migrate() {
	// Migrate the schema
	initials.DB.AutoMigrate(
		&User{},
		&Room{},
		&RoomUser{},
		&Message{},
		&Attachment{},
	)
}
