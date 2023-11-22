package main

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
	"strconv"
	"time"
)

func main() {
	// Gorm instance
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
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

	// Echo instance
	e := echo.New()
	e.IPExtractor = echo.ExtractIPFromXFFHeader()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:  []string{"*"},
		ExposeHeaders: []string{"ETag"},
		AllowHeaders:  []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	// etag assign api
	e.GET("/", func(c echo.Context) error {
		// fetch ip
		ip := c.RealIP()
		// Fingerprint
		fingerprint := c.QueryParam("fingerprint")
		if fingerprint == "" {
			return errors.New("fingerprint is not provided")
		}
		// Fetch user agent
		userAgent := c.Request().UserAgent()
		// Old E-tag
		oldEtag := c.Request().Header.Get("If-None-Match")
		response := c.Response()
		if oldEtag != "" {
			entryStatus := ETagLogEntry(db, oldEtag, ip, userAgent, fingerprint)
			if entryStatus == false {
				log.Println("ETag log entry failed")
			}
			// Send response
			response.Header().Set("ETag", oldEtag)
			response.Status = 304
			response.Flush()
			return nil
		} else {
			var etag string

			// stage limit
			stageLimit := c.QueryParam("stage_limit")
			if stageLimit == "" {
				return errors.New("stage_limit is not provided")
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
			if entryStatus == false {
				log.Println("ETag log entry failed")
			}
			// Send response
			response.Header().Set("ETag", etag)
			_, err := response.Write([]byte(etag))
			if err != nil {
				return err
			}
			response.Status = 200
			response.Flush()
			return nil
		}
	})

	e.Logger.Fatal(e.Start(":8080"))
}