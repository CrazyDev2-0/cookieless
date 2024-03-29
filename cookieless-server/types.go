package main

type IPInfo struct {
	IP            string `json:"ip" gorm:"primaryKey"`
	ContinentCode string `json:"continent_code"`
	CountryCode   string `json:"country_code"`
	RegionCode    string `json:"region_code"`
	ZipCode       string `json:"zip_code"`
	ASNAME        string `json:"asname"`
	IsMobile      bool   `json:"is_mobile"`
}

type UserTokenLog struct {
	ID           int64  `json:"id" gorm:"primaryKey"`
	UserToken    string `json:"user_token"`
	IP           string `json:"ip"`
	UserAgent    string `json:"user_agent"`
	Fingerprint  string `json:"fingerprint"`
	UTCTimestamp int64  `json:"utc_timestamp"`
}
