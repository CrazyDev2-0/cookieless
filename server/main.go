package main

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
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
			etag := GenerateETag()

			// TODO: try to find old etag and reassociate

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

	// GET /related/:etag?confidence=0.5
	// TODO: fetch possible etags from database

	e.Logger.Fatal(e.Start(":8080"))
}
