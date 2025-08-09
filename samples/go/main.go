package main

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func main() {
	_ = jwt.New(jwt.SigningMethodHS256)
	r := gin.Default()
	r.GET("/", func(c *gin.Context) { c.String(200, "Hello, Gin!") })
	r.Run()
}
