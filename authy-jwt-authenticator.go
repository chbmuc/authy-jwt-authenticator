package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/dcu/go-authy"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mssola/user_agent"
	"github.com/spf13/viper"
)

var authyAPI *authy.Authy

var conf = viper.New()

const loginPage = `
<html>
<head>
    <title>Login</title>
	<style>
		* {
		box-sizing: border-box;
		-moz-box-sizing: border-box;
		-webkit-box-sizing: border-box;
		font-family: arial;
		}

		body {
		background: #FFFFFF;
		}

		.login-form {
		width: 350px;
		padding: 40px 30px;
		background: #eee;
		-moz-border-radius: 4px;
		-webkit-border-radius: 4px;
		border-radius: 4px;
		margin: auto;
		position: absolute;
		left: 0;
		right: 0;
		top: 50%;
		-moz-transform: translateY(-50%);
		-ms-transform: translateY(-50%);
		-webkit-transform: translateY(-50%);
		transform: translateY(-50%);
		}

		.form-group {
		position: relative;
		margin-bottom: 15px;
		}

		.form-control {
		width: 290px;
		height: 50px;
		border: none;
		padding: 5px 7px 5px 15px;
		background: #fff;
		color: #666;
		border: 2px solid #ddd;
		-moz-border-radius: 4px;
		-webkit-border-radius: 4px;
		border-radius: 4px;
		}
		.form-control:focus, .form-control:focus + .fa {
		border-color: #10CE88;
		color: #10CE88;
		}

		.form-group .fa {
		position: absolute;
		right: 15px;
		top: 17px;
		color: #999;
		}

		.log-status.wrong-entry .form-control, .wrong-entry .form-control + .fa {
		border-color: #ed1c24;
		color: #ed1c24;
		}

		.log-btn {
		background: #0AC986;
		display: inline-block;
		width: 290px;
		font-size: 16px;
		height: 50px;
		color: #fff;
		text-decoration: none;
		border: none;
		-moz-border-radius: 4px;
		-webkit-border-radius: 4px;
		border-radius: 4px;
		}

		.alert {
		height: 30px;
		font-size: 12px;
		color: #f00;
		float: left;
		}
	</style>
</head>
<body>
<form method="post" action="/_login/req">
<div class="login-form">
     <div class="form-group log-status {{.WrongEntry}}">
       <input type="text" class="form-control" placeholder="Username " id="user" name="user">
       <i class="fa fa-user"></i>
     </div>
	 <input type="hidden" name="service" value="{{.Service}}">
	 <input type="hidden" name="subject" value="{{.Subject}}">
	 <input type="hidden" name="redirect" value="{{.Redirect}}">
     <div class="alert">{{.Error}}</div>
     <button type="submit" class="log-btn" >Log in</button>
</div>
</form>
</body>
`

type page struct {
	Error      string
	WrongEntry string
	Service    string
	Subject    string
	Redirect   string
}

func loginPageHandler(response http.ResponseWriter, request *http.Request) {
	errorMsg := request.FormValue("error")
	service := request.FormValue("service")
	subject := request.FormValue("subject")
	redirect := request.FormValue("redirect")

	// use the referer if no redirect is given
	if len(redirect) == 0 {
		redirect = request.Referer()
	}

	t, err := template.New("loginpage").Parse(loginPage)
	if err != nil {
		fmt.Println(err)
	}

	p := &page{Service: "JWT Authentication Server"}

	if len(errorMsg) > 0 {
		p.Error = errorMsg
		p.WrongEntry = "wrong-entry"
	}

	if len(service) > 0 {
		p.Service = service
	}

	if len(subject) > 0 {
		p.Subject = subject
	}

	if len(redirect) > 0 {
		p.Redirect = redirect
	}

	err = t.Execute(response, p)
	if err != nil {
		fmt.Println(err)
	}
}

func successPageHandler(response http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(response, "Success!")
}

func getApprovalHandler(response http.ResponseWriter, request *http.Request) {
	user := request.FormValue("user")
	service := request.FormValue("service")
	subject := request.FormValue("subject")
	redirect := request.FormValue("redirect")
	forward := request.Header.Get("X-Forwarded-For")

	// send Authy approval request
	details := authy.Details{
		"Type": "Unknown service",
	}

	authyID := conf.GetString("DefaultAuthyID")

	if len(service) > 0 {
		details["Type"] = service
	}
	if len(user) == 0 {
		user = "<unknown>"
	}
	details["User"] = user

	if len(forward) > 0 {
		details["User IP"] = forward
	} else {
		details["User IP"] = request.RemoteAddr
	}

	ua := user_agent.New(request.UserAgent())
	browser, _ := ua.Browser()
	details["User Agent"] = fmt.Sprintf("%v (%v)", browser, ua.OSInfo().Name)

	approvalRequest, err := authyAPI.SendApprovalRequest(authyID, "Log to your server", details, url.Values{})
	if err != nil {
		fmt.Println(err)
		redirectTarget := "/_login?error=" + url.QueryEscape("Failure while sending approval request") + "&redirect=" + url.QueryEscape(redirect) + "&subject=" + url.QueryEscape(subject) + "&user=" + url.QueryEscape(user) + "&service=" + url.QueryEscape(service)
		http.Redirect(response, request, redirectTarget, 302)
	} else {
		redirectTarget := "/_login/wait?uuid=" + approvalRequest.UUID + "&redirect=" + url.QueryEscape(redirect) + "&subject=" + url.QueryEscape(subject) + "&user=" + url.QueryEscape(user) + "&service=" + url.QueryEscape(service)
		http.Redirect(response, request, redirectTarget, 302)
	}
}

func waitHandler(response http.ResponseWriter, request *http.Request) {
	user := request.FormValue("user")
	uuid := request.FormValue("uuid")
	service := request.FormValue("service")
	subject := request.FormValue("subject")
	redirect := request.FormValue("redirect")

	redirectTarget := "/_login/wait?uuid=" + uuid + "&redirect=" + url.QueryEscape(redirect) + "&subject=" + url.QueryEscape(subject) + "&user=" + url.QueryEscape(user) + "&service=" + url.QueryEscape(service)

	status, err := authyAPI.WaitForApprovalRequest(uuid, 45*time.Second, url.Values{})
	if status == authy.OneTouchStatusApproved {
		if len(redirect) > 0 {
			redirectTarget = redirect
		} else {
			redirectTarget = "/_login/success"
		}

		// Set JWT cookie
		expiration := time.Now().Add(365 * 24 * time.Hour)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"sub":  subject,
			"exp":  expiration.Unix(),
		})

		mySigningKey := conf.GetString("SigningKey")
		tokenString, err := token.SignedString([]byte(mySigningKey))

		if err != nil {
			redirectTarget = "/_login?error=" + url.QueryEscape("Error generating token") + "&redirect=" + url.QueryEscape(redirect) + "&subject=" + url.QueryEscape(subject) + "&user=" + url.QueryEscape(user) + "&service=" + url.QueryEscape(service)
		} else {
			//cookie := http.Cookie{Name: "jwt_token", Value: tokenString, Expires: expiration, Secure: true}
			cookie := http.Cookie{Name: "jwt_token", Value: tokenString, Expires: expiration}
			http.SetCookie(response, &cookie)
		}
	}

	if status == authy.OneTouchStatusDenied {
		redirectTarget = "/_login?error=" + url.QueryEscape("Access denied") + "&redirect=" + url.QueryEscape(redirect) + "&subject=" + url.QueryEscape(subject) + "&user=" + url.QueryEscape(user) + "&service=" + url.QueryEscape(service)
	}

	if err != nil {
		fmt.Println(err)
		redirectTarget = "/_login?error=" + url.QueryEscape("Unable to get approval") + "&redirect=" + url.QueryEscape(redirect) + "&subject=" + url.QueryEscape(subject) + "&user=" + url.QueryEscape(user) + "&service=" + url.QueryEscape(service)
	}

	http.Redirect(response, request, redirectTarget, 302)
}

func main() {
	conf.SetConfigName("config")
	conf.AddConfigPath("/etc/authy-jwt-authenticator/")
	conf.AddConfigPath(".")

	err := conf.ReadInConfig() // Find and read the config file
	if err != nil {            // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	apiKey := conf.GetString("AuthyAPI")

	authyAPI = authy.NewAuthyAPI(apiKey)

	http.HandleFunc("/_login", loginPageHandler)
	http.HandleFunc("/_login/req", getApprovalHandler)
	http.HandleFunc("/_login/wait", waitHandler)
	http.HandleFunc("/_login/success", successPageHandler)

	fmt.Println("Serving authy login-page at http://localhost:8080/_login")
	http.ListenAndServe(":8080", nil)
}
