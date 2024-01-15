package main

import (
	_ "embed"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
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
	err = db.AutoMigrate(&ETagLog{})
	if err != nil {
		panic("failed to migrate database")
	}

	verificationRequests := make(map[string]string, 100) // map[random_token]response_token(same as e-tag)

	// Echo instance
	e := echo.New()
	e.IPExtractor = echo.ExtractIPFromXFFHeader()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:  []string{"*"},
		ExposeHeaders: []string{"ETag"},
		AllowHeaders:  []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	// Prepare the cookieless js
	serverEndpoint := os.Getenv("SERVER_ENDPOINT")
	if serverEndpoint == "" {
		panic("SERVER_ENDPOINT is not provided")
	}

	cookielessJs = strings.Replace(cookielessJs, "{SERVER_ENDPOINT}", serverEndpoint, -1)

	// Endpoints

	// etag assign api
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
		// Old E-tag
		oldEtag := c.Request().Header.Get("If-None-Match")
		availableCookies := c.Cookies()
		if len(availableCookies) > 0 {
			for _, c := range availableCookies {
				if c.Name == "__Host-cookieless-token" {
					oldEtag = c.Value
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
		if oldEtag != "" {
			entryStatus := ETagLogEntry(db, oldEtag, ip, userAgent, fingerprint)
			if !entryStatus {
				log.Println("ETag log entry failed")
			}
			// Send response
			response.Header().Set("ETag", oldEtag)
			response.Header().Set(echo.HeaderSetCookie, GenerateCookie(oldEtag))
			response.Status = 304
			response.Writer.Write([]byte(""))
			response.Flush()
			// update result in database
			if isImage {
				if _, ok := verificationRequests[token]; ok {
					verificationRequests[token] = oldEtag
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

			var etag string

			// stage limit
			stageLimit := c.QueryParam("stage_limit")
			if stageLimit == "" {
				return c.String(400, "stage_limit is not provided")
			}
			// stage limit int
			stageLimitInt, _ := strconv.Atoi(stageLimit)
			// try to find etag

			// useragent system details
			systemDetailsUserAgent := FetchSystemInfoFromUserAgent(userAgent)

			// fetch ipinfo
			ipInfo, _ := FetchIPInfo(db, ip)
			etag = GetNearestEtag(db, fingerprint, *ipInfo, systemDetailsUserAgent, time.Now().UTC().Unix(), stageLimitInt)
			if etag == "" {
				etag = GenerateETag()
			}
			// log entry
			entryStatus := ETagLogEntry(db, etag, ip, userAgent, fingerprint)
			if !entryStatus {
				log.Println("ETag log entry failed")
			}
			// Send response
			response.Header().Set("ETag", etag)
			response.Header().Set(echo.HeaderSetCookie, GenerateCookie(etag))
			_, err := response.Write([]byte(etag))
			if err != nil {
				return err
			}
			response.Status = 200
			response.Writer.Write([]byte(""))
			response.Flush()
			if isImage {
				if _, ok := verificationRequests[token]; ok {
					verificationRequests[token] = etag
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
