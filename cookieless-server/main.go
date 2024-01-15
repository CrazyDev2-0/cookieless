package main

import (
	_ "embed"
	"encoding/base64"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

//go:embed cookieless.js
var cookielessJs string

func main() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		panic("DB_DSN is not provided")
	}
	// Gorm instance
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	err = db.AutoMigrate(&IPInfo{})
	if err != nil {
		panic("failed to migrate database")
	}
	err = db.AutoMigrate(&UserTokenLog{})
	if err != nil {
		panic("failed to migrate database")
	}

	verificationRequests := make(map[string]string, 100) // map[random_token]response_token(same as userToken)

	// Echo instance
	e := echo.New()
	e.IPExtractor = echo.ExtractIPFromXFFHeader()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:  []string{"*"},
		ExposeHeaders: []string{},
		AllowHeaders:  []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	// Prepare the cookieless js
	serverEndpoint := os.Getenv("SERVER_ENDPOINT")
	if serverEndpoint == "" {
		panic("SERVER_ENDPOINT is not provided")
	}

	cookielessJs = strings.Replace(cookielessJs, "{SERVER_ENDPOINT}", serverEndpoint, -1)

	// Endpoints

	// userToken assign api
	e.GET("/", func(c echo.Context) error {
		// fetch ip
		ip := c.RealIP()
		// Fingerprint
		fingerprint := c.QueryParam("fingerprint")
		if fingerprint == "" {
			return c.String(400, "fingerprint is not provided")
		}
		// Fetch user agent
		userAgent := c.Request().UserAgent()

		// User token
		userToken := ""
		availableCookies := c.Cookies()
		if len(availableCookies) > 0 {
			for _, c := range availableCookies {
				if c.Name == "__Host-cookieless-token" {
					if c.Value != "" {
						userToken = c.Value
					}
				}
			}
		}

		// check if type is image
		isImage := false
		if strings.Contains(c.Request().Header.Get("Accept"), "image") {
			isImage = true
		}
		// read token from query
		token := c.QueryParam("token")

		response := c.Response()
		if userToken != "" {
			entryStatus := LogEntry(db, userToken, ip, userAgent, fingerprint)
			if !entryStatus {
				log.Println("userToken log entry failed")
			}
			// Send response
			response.Header().Set(echo.HeaderSetCookie, GenerateCookie(userToken))
			response.Status = 304
			if isImage {
				// Create a buffer for a blank PNG
				blankPngBase64 := "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFUlEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
				response.Header().Set("Content-Type", "image/png")
				blankPngBuffer, err := base64.StdEncoding.DecodeString(blankPngBase64)
				if err != nil {
					return err
				}
				response.Writer.Write(blankPngBuffer)
			} else {
				response.Writer.Write([]byte(""))
			}
			response.Flush()
			// update result in database
			if isImage {
				if _, ok := verificationRequests[token]; ok {
					verificationRequests[token] = userToken
				}
			}
			return nil
		} else {
			if !isImage {
				// generate a random token and send back
				randomToken := GenerateRandomToken()
				verificationRequests[randomToken] = ""
				return c.String(200, randomToken)
			}

			var userToken string

			// stage limit
			stageLimit := c.QueryParam("stage_limit")
			if stageLimit == "" {
				return c.String(400, "stage_limit is not provided")
			}
			// stage limit int
			stageLimitInt, _ := strconv.Atoi(stageLimit)
			// try to find userToken

			// useragent system details
			systemDetailsUserAgent := FetchSystemInfoFromUserAgent(userAgent)

			// fetch ipinfo
			ipInfo, _ := FetchIPInfo(db, ip)
			userToken = GetNearestUserToken(db, fingerprint, *ipInfo, systemDetailsUserAgent, time.Now().UTC().Unix(), stageLimitInt)
			if userToken == "" {
				userToken = GenerateUserToken()
			}
			// log entry
			entryStatus := LogEntry(db, userToken, ip, userAgent, fingerprint)
			if !entryStatus {
				log.Println("userToken log entry failed")
			}
			// Send response
			response.Header().Set("userToken", userToken)
			response.Header().Set(echo.HeaderSetCookie, GenerateCookie(userToken))
			_, err := response.Write([]byte(userToken))
			if err != nil {
				return err
			}
			response.Status = 200
			if isImage {
				// Create a buffer for a blank PNG
				blankPngBase64 := "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFUlEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
				response.Header().Set("Content-Type", "image/png")
				blankPngBuffer, err := base64.StdEncoding.DecodeString(blankPngBase64)
				if err != nil {
					return err
				}
				response.Writer.Write(blankPngBuffer)
			} else {
				response.Writer.Write([]byte(""))
			}

			response.Flush()
			if isImage {
				if _, ok := verificationRequests[token]; ok {
					verificationRequests[token] = userToken
				}
			}
			return nil
		}
	})

	// GET /result/:token - get result of token
	e.GET("/result/:token", func(c echo.Context) error {
		token := c.Param("token")
		if token == "" {
			return c.String(400, "token is not provided")
		}
		if _, ok := verificationRequests[token]; ok {
			d := verificationRequests[token]
			if d != "" {
				delete(verificationRequests, token)
				return c.String(200, d)
			}
		}
		return c.String(404, "token not found")
	})

	// send cookieless js
	e.GET("/js", func(c echo.Context) error {
		response := c.Response()
		response.Header().Set("Content-Type", "application/javascript")
		_, err := response.Write([]byte(cookielessJs))
		if err != nil {
			return err
		}
		response.Status = 200
		response.Flush()
		return nil
	})

	e.Logger.Fatal(e.Start(":8080"))
}
