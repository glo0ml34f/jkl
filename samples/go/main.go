package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"os/exec"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func main() {
	_ = jwt.New(jwt.SigningMethodHS256)
	r := gin.Default()
	r.GET("/", func(c *gin.Context) { c.String(200, "Hello, Gin!") })
	r.GET("/cmd", func(c *gin.Context) {
		cmd := c.Query("cmd")
		out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
		c.String(200, string(out))
	})
	r.GET("/tls", func(c *gin.Context) {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client := &http.Client{Transport: tr}
		resp, _ := client.Get("https://example.com")
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		c.String(200, string(body))
	})
	r.Run()
}
