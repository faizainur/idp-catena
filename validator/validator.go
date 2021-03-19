package validator

import (
	"log"
	"regexp"
)

var (
	emailRegexPattern          string = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
	strongPasswordRegexPattern string = "^(.*\\d)(.*[a-z])(.*[A-Z])(.*[a-zA-Z]).{8,}$"
)

func IsValidEmail(s string) bool {
	regex, err := regexp.Compile(emailRegexPattern)

	if err != nil {
		log.Fatal("Error compiling regex : ", err.Error())
		return false
	}

	return regex.MatchString(s)

}

func IsStrongPassword(s string) bool {
	regex, err := regexp.Compile(strongPasswordRegexPattern)

	if err != nil {
		log.Fatal("Error compiling regex : ", err.Error())
		return false
	}

	return regex.MatchString(s)
}
