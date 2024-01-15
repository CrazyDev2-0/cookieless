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

func GenerateRandomToken() string {
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
	ipInfo.ZipCode = result["zip"].(string)
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

/*
Stages -
Stage 1 > fingerprint, useragent, ip are same, return old etag
Stage 2 > fingerprint, useragent are same, find out latest log in past 60 seconds, Action : if found, return etag
Stage 3 > fingerprint, useragent, IsMobile, ZIP code, ASNAME are same, Action : if found, return etag
Stage 4 > fingerprint, useragent, IsMobile, RegionCode, ASNAME are same, Action : if found, return etag
Stage 5 > fingerprint, useragent, IsMobile, CountryCode, ASNAME are same, Action : if found, return etag
Stage 6 > fingerprint, useragent, ZIP code are same, Action : if found, return etag
Stage 7 > fingerprint, useragent, RegionCode are same, Action : if found, return etag
Stage 8 > fingerprint, useragent, CountryCode are same, Action : if found, return etag
Stage 9 > fingerprint, useragent, ContinentCode are same, Action : if found, return etag
Stage 10 > fingerprint, useragent are same, Action : if found, return etag
*/

func GetNearestEtag(db *gorm.DB, fingerprint string, ipInfo IPInfo, useragent string, timestamp int64, stageLimit int) string {
	var etagLog = ETagLog{}
	// Stage 1
	tx := db.Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip = ?", ipInfo.IP).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 1 {
		return ""
	}
	// Stage 2
	tx = db.Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("utc_timestamp >= ?", timestamp-60).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 2 {
		return ""
	}
	// Stage 3
	tx = db.Joins("JOIN ip_infos on ip_infos.ip = e_tag_logs.ip").Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip_infos.is_mobile = ?", ipInfo.IsMobile).Where("ip_infos.zip_code = ?", ipInfo.ZipCode).Where("ip_infos.asname = ?", ipInfo.ASNAME).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 3 {
		return ""
	}
	// Stage 4
	tx = db.Joins("JOIN ip_infos on ip_infos.ip = e_tag_logs.ip").Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip_infos.is_mobile = ?", ipInfo.IsMobile).Where("ip_infos.region_code = ?", ipInfo.RegionCode).Where("ip_infos.asname = ?", ipInfo.ASNAME).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 4 {
		return ""
	}
	// Stage 5
	tx = db.Joins("JOIN ip_infos on ip_infos.ip = e_tag_logs.ip").Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip_infos.is_mobile = ?", ipInfo.IsMobile).Where("ip_infos.country_code = ?", ipInfo.CountryCode).Where("ip_infos.asname = ?", ipInfo.ASNAME).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 5 {
		return ""
	}
	// Stage 6
	tx = db.Joins("JOIN ip_infos on ip_infos.ip = e_tag_logs.ip").Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip_infos.zip_code = ?", ipInfo.ZipCode).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 6 {
		return ""
	}
	// Stage 7
	tx = db.Joins("JOIN ip_infos on ip_infos.ip = e_tag_logs.ip").Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip_infos.region_code = ?", ipInfo.RegionCode).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 7 {
		return ""
	}
	// Stage 8
	tx = db.Joins("JOIN ip_infos on ip_infos.ip = e_tag_logs.ip").Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip_infos.country_code = ?", ipInfo.CountryCode).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 8 {
		return ""
	}
	// Stage 9
	tx = db.Joins("JOIN ip_infos on ip_infos.ip = e_tag_logs.ip").Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Where("ip_infos.continent_code = ?", ipInfo.ContinentCode).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	if stageLimit == 9 {
		return ""
	}
	// Stage 10
	tx = db.Where("fingerprint = ?", fingerprint).Where("user_agent = ?", useragent).Order("utc_timestamp desc").First(&etagLog)
	if tx.Error == nil {
		return etagLog.Etag
	}
	return ""
}

func GenerateCookie(value string) string {
	cookie := &http.Cookie{
		Name:     "__Host-cookieless-token",
		Value:    value,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		Path:     "/",
		HttpOnly: true,
	  }
  
	  // Manually add the "Partitioned" attribute
	  cookieStr := cookie.String() + "; Partitioned;"
	  return cookieStr
}