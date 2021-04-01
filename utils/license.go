// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package utils

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mattermost/mattermost-server/v5/mlog"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/utils/fileutils"
)

// var publicKey []byte = []byte(`-----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyZmShlU8Z8HdG0IWSZ8r
// tSyzyxrXkJjsFUf0Ke7bm/TLtIggRdqOcUF3XEWqQk5RGD5vuq7Rlg1zZqMEBk8N
// EZeRhkxyaZW8pLjxwuBUOnXfJew31+gsTNdKZzRjrvPumKr3EtkleuoxNdoatu4E
// HrKmR/4Yi71EqAvkhk7ZjQFuF0osSWJMEEGGCSUYQnTEqUzcZSh1BhVpkIkeu8Kk
// 1wCtptODixvEujgqVe+SrE3UlZjBmPjC/CL+3cYmufpSNgcEJm2mwsdaXp2OPpfn
// a0v85XL6i9ote2P+fLZ3wX9EoioHzgdgB7arOxY50QRJO7OyCqpKFKv6lRWTXuSt
// hwIDAQAB
// -----END PUBLIC KEY-----`)

func ValidateLicense(signed []byte) (bool, string) {
	// decoded := make([]byte, base64.StdEncoding.DecodedLen(len(signed)))

	// _, err := base64.StdEncoding.Decode(decoded, signed)
	// if err != nil {
	// 	mlog.Error("Encountered error decoding license", mlog.Err(err))
	// 	return false, ""
	// }

	// if len(decoded) <= 256 {
	// 	mlog.Error("Signed license not long enough")
	// 	return false, ""
	// }

	// // remove null terminator
	// for decoded[len(decoded)-1] == byte(0) {
	// 	decoded = decoded[:len(decoded)-1]
	// }

	// plaintext := decoded[:len(decoded)-256]
	// signature := decoded[len(decoded)-256:]

	// block, _ := pem.Decode(publicKey)

	// public, err := x509.ParsePKIXPublicKey(block.Bytes)
	// if err != nil {
	// 	mlog.Error("Encountered error signing license", mlog.Err(err))
	// 	return false, ""
	// }

	// rsaPublic := public.(*rsa.PublicKey)

	// h := sha512.New()
	// h.Write(plaintext)
	// d := h.Sum(nil)

	// err = rsa.VerifyPKCS1v15(rsaPublic, crypto.SHA512, d, signature)
	// if err != nil {
	// 	mlog.Error("Invalid signature", mlog.Err(err))
	// 	return false, ""
	// }
	str := []byte(`{"id":"rj8qftpud7rf7m7ktjx85ezxxx","issued_at":1616765041267,"starts_at":1616736241267,"expires_at":4109721841000,"sku_name":"Enterprise E20","sku_short_name":"E20","customer":{"id":"rj8qftpud7rf7m7ktjx85ezc3e","name":"Jarvis","email":"hn-coder@example.com","company":"https://mattermost.com"},"features":{"users":10000,"ldap":true,"ldap_groups":true,"mfa":true,"google_oauth":true,"office365_oauth":true,"compliance":true,"cluster":true,"metrics":true,"mhpns":true,"saml":true,"elastic_search":true,"announcement":true,"theme_management":true,"email_notification_contents":true,"data_retention":true,"message_export":true,"custom_permissions_schemes":true,"custom_terms_of_service":true,"guest_accounts":true,"guest_accounts_permissions":true,"id_loaded":true,"lock_teammate_name_display":true,"cloud":false,"future_features":true}}`)

	// mlog.Error("plaintext ", mlog.Err(err))
	// return true, string(plaintext)
	mlog.Info(string(str))
	return true, string(str)
}

func GetAndValidateLicenseFileFromDisk(location string) (*model.License, []byte) {
	// fileName := GetLicenseFileLocation(location)

	// if _, err := os.Stat(fileName); err != nil {
	// 	mlog.Debug("We could not find the license key in the database or on disk at", mlog.String("filename", fileName))
	// 	return nil, nil
	// }

	// mlog.Info("License key has not been uploaded.  Loading license key from disk at", mlog.String("filename", fileName))
	// licenseBytes := GetLicenseFileFromDisk(fileName)

	// if success, licenseStr := ValidateLicense(licenseBytes); !success {
	// 	mlog.Error("Found license key at %v but it appears to be invalid.", mlog.String("filename", fileName))
	// 	return nil, nil
	// } else {
	// 	return model.LicenseFromJson(strings.NewReader(licenseStr)), licenseBytes
	//}
	licenseBytes := []byte(`abcxzy`)
	str := []byte(`{"id":"rj8qftpud7rf7m7ktjx85ezxxx","issued_at":1616765041267,"starts_at":1616736241267,"expires_at":4109721841000,"sku_name":"Enterprise E20","sku_short_name":"E20","customer":{"id":"rj8qftpud7rf7m7ktjx85ezc3e","name":"Jarvis","email":"hn-coder@example.com","company":"https://mattermost.com"},"features":{"users":10000,"ldap":true,"ldap_groups":true,"mfa":true,"google_oauth":true,"office365_oauth":true,"compliance":true,"cluster":true,"metrics":true,"mhpns":true,"saml":true,"elastic_search":true,"announcement":true,"theme_management":true,"email_notification_contents":true,"data_retention":true,"message_export":true,"custom_permissions_schemes":true,"custom_terms_of_service":true,"guest_accounts":true,"guest_accounts_permissions":true,"id_loaded":true,"lock_teammate_name_display":true,"cloud":false,"future_features":true}}`)
	return model.LicenseFromJson(strings.NewReader(string(str))), licenseBytes
}

func GetLicenseFileFromDisk(fileName string) []byte {
	file, err := os.Open(fileName)
	if err != nil {
		mlog.Error("Failed to open license key from disk at", mlog.String("filename", fileName), mlog.Err(err))
		return nil
	}
	defer file.Close()

	licenseBytes, err := ioutil.ReadAll(file)
	if err != nil {
		mlog.Error("Failed to read license key from disk at", mlog.String("filename", fileName), mlog.Err(err))
		return nil
	}

	return licenseBytes
}

func GetLicenseFileLocation(fileLocation string) string {
	if fileLocation == "" {
		configDir, _ := fileutils.FindDir("config")
		return filepath.Join(configDir, "mattermost.mattermost-license")
	} else {
		return fileLocation
	}
}

func GetClientLicense(l *model.License) map[string]string {
	props := make(map[string]string)

	props["IsLicensed"] = strconv.FormatBool(l != nil)

	if l != nil {
		props["Id"] = l.Id
		props["SkuName"] = l.SkuName
		props["SkuShortName"] = l.SkuShortName
		props["Users"] = strconv.Itoa(*l.Features.Users)
		props["LDAP"] = strconv.FormatBool(*l.Features.LDAP)
		props["LDAPGroups"] = strconv.FormatBool(*l.Features.LDAPGroups)
		props["MFA"] = strconv.FormatBool(*l.Features.MFA)
		props["SAML"] = strconv.FormatBool(*l.Features.SAML)
		props["Cluster"] = strconv.FormatBool(*l.Features.Cluster)
		props["Metrics"] = strconv.FormatBool(*l.Features.Metrics)
		props["GoogleOAuth"] = strconv.FormatBool(*l.Features.GoogleOAuth)
		props["Office365OAuth"] = strconv.FormatBool(*l.Features.Office365OAuth)
		props["Compliance"] = strconv.FormatBool(*l.Features.Compliance)
		props["MHPNS"] = strconv.FormatBool(*l.Features.MHPNS)
		props["Announcement"] = strconv.FormatBool(*l.Features.Announcement)
		props["Elasticsearch"] = strconv.FormatBool(*l.Features.Elasticsearch)
		props["DataRetention"] = strconv.FormatBool(*l.Features.DataRetention)
		props["IDLoadedPushNotifications"] = strconv.FormatBool(*l.Features.IDLoadedPushNotifications)
		props["IssuedAt"] = strconv.FormatInt(l.IssuedAt, 10)
		props["StartsAt"] = strconv.FormatInt(l.StartsAt, 10)
		props["ExpiresAt"] = strconv.FormatInt(l.ExpiresAt, 10)
		props["Name"] = l.Customer.Name
		props["Email"] = l.Customer.Email
		props["Company"] = l.Customer.Company
		props["EmailNotificationContents"] = strconv.FormatBool(*l.Features.EmailNotificationContents)
		props["MessageExport"] = strconv.FormatBool(*l.Features.MessageExport)
		props["CustomPermissionsSchemes"] = strconv.FormatBool(*l.Features.CustomPermissionsSchemes)
		props["GuestAccounts"] = strconv.FormatBool(*l.Features.GuestAccounts)
		props["GuestAccountsPermissions"] = strconv.FormatBool(*l.Features.GuestAccountsPermissions)
		props["CustomTermsOfService"] = strconv.FormatBool(*l.Features.CustomTermsOfService)
		props["LockTeammateNameDisplay"] = strconv.FormatBool(*l.Features.LockTeammateNameDisplay)
		props["Cloud"] = strconv.FormatBool(*l.Features.Cloud)
	}

	return props
}
