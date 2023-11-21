package main

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"io"
	"log"
	"net/http"
	"regexp"
	"time"
)

func GenerateETag() string {
	return uuid.NewString()
}

func IsExistIPInfo(db *gorm.DB, ip string) bool {
	var ipInfo IPInfo
	tx := db.First(&ipInfo, "ip = ?", ip)
	if tx.Error != nil {
		return false
	}
	return true
}

func FetchIPInfo(db *gorm.DB, ip string) (*IPInfo, error) {
	var ipInfo IPInfo
	tx := db.First(&ipInfo, "ip = ?", ip)
	if tx.Error != nil && !errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return nil, errors.New("database error")
	}
	if tx.Error == nil {
		return &ipInfo, nil
	}
	// If record not found, fetch from API
	apiEndpoint := "http://ip-api.com/json/" + ip + "?fields=status,continentCode,countryCode,region,zip,asname,mobile,query"
	// send request
	resp, err := http.Get(apiEndpoint)
	if err != nil {
		return nil, errors.New("API error")
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)
	// decode response as string
	contentBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal(contentBytes, &result)
	if err != nil {
		return nil, err
	}
	// check status
	if result["status"] != "success" {
		return nil, errors.New("API error")
	}
	// parse result
	ipInfo.IP = ip
	ipInfo.ContinentCode = result["continentCode"].(string)
	ipInfo.CountryCode = result["countryCode"].(string)
	ipInfo.RegionCode = result["region"].(string)
	ipInfo.ZIPCode = result["zip"].(string)
	ipInfo.ASNAME = result["asname"].(string)
	ipInfo.IsMobile = result["mobile"].(bool)
	// store to database
	tx = db.Save(&ipInfo)
	if tx.Error != nil {
		return nil, errors.New("database error")
	}
	return &ipInfo, nil
}

var compiledRegex = regexp.MustCompile(`\((.*?)(?:\s*rv:|\))`)

func FetchSystemInfoFromUserAgent(userAgent string) string {
	// regex : \((.*?)(?:\s*rv:|\))
	if userAgent == "" {
		return ""
	}
	matches := compiledRegex.FindStringSubmatch(userAgent)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func ETagLogEntry(db *gorm.DB, etag string, ip string, useragent string, fingerprint string) bool {
	if !IsExistIPInfo(db, ip) {
		_, err := FetchIPInfo(db, ip)
		if err != nil {
			log.Println(err)
		}
	}
	var etagLog ETagLog
	etagLog.Etag = etag
	etagLog.IP = ip
	etagLog.UserAgent = FetchSystemInfoFromUserAgent(useragent)
	etagLog.Fingerprint = fingerprint
	etagLog.UTCTimestamp = time.Now().UTC().Unix()
	tx := db.Save(&etagLog)
	if tx.Error != nil {
		return false
	}
	return true
}
