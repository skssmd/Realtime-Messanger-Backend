package controlers

import (
	"base/initials"
	"net/http"

	"github.com/gin-gonic/gin"
)

func SearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query cannot be empty"})
		return
	}

	var users []struct {
		ID       uint   `json:"id"`
		Email    string `json:"email"`
		Username string `json:"username"`
		Name     string `json:"name"`
	}

	err := initials.DB.Table("users").
		Select("id, email, username, CONCAT(first_name, ' ', last_name) AS name").
		Where("LOWER(first_name) LIKE LOWER(?) OR LOWER(last_name) LIKE LOWER(?) OR LOWER(username) LIKE LOWER(?) OR LOWER(CONCAT(first_name, ' ', last_name)) LIKE LOWER(?)",
			"%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%").
		Find(&users).Error

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}
