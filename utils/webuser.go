package utils

import (
	"net/mail"
)

type WebUser struct {
	Email           string
	FirstName       string
	LastName        string
	Password        string
	PasswordConfirm string
	Errors          map[string]string
}

func (webU *WebUser) Validate() bool {
	webU.Errors = make(map[string]string)

	_, err := mail.ParseAddress(webU.Email)
	if err != nil {
		webU.Errors["Email"] = "Please enter a valid email address"
	}

	if webU.FirstName == "" || webU.LastName == "" {
		webU.Errors["Name"] = "First name and last name cannot be empty"
	}

	if webU.Password != webU.PasswordConfirm {
		webU.Errors["Password"] = "Passwords do not match, try again"
	}

	return len(webU.Errors) == 0
}
