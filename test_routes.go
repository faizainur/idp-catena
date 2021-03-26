package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)


func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "Server is running",
	})
}

func securedEndpoint(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":   "Server is running",
		"email":    c.GetString("email"),
		"user_uid": c.GetString("userUid"),
	})
}