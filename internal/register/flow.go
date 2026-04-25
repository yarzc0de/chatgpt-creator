package register

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/verssache/chatgpt-creator/internal/email"
	"github.com/verssache/chatgpt-creator/internal/util"
)

// visitHomepage visits chatgpt.com to initialize session
func (c *Client) visitHomepage() error {
	var resp *http.Response
	var err error
	for retry := 0; retry < 3; retry++ {
		req, _ := http.NewRequest("GET", baseURL+"/", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		resp, err = c.do(req)
		if err != nil {
			return err
		}

		c.log(fmt.Sprintf("Visit Homepage (Try %d)", retry+1), resp.StatusCode)

		if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 307 {
			resp.Body.Close()
			return nil
		}
		resp.Body.Close()
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("failed to visit homepage after 3 retries (status: %d)", resp.StatusCode)
}

// getCSRF retrieves the CSRF token from chatgpt.com
func (c *Client) getCSRF() (string, error) {
	req, _ := http.NewRequest("GET", baseURL+"/api/auth/csrf", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", baseURL+"/")

	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}

	c.log("Get CSRF", resp.StatusCode)
	if data.CSRFToken == "" {
		return "", fmt.Errorf("csrf token not found")
	}
	return data.CSRFToken, nil
}

// signin initiates the signin process and returns the authorize URL
func (c *Client) signin(email, csrf string) (string, error) {
	signinURL := baseURL + "/api/auth/signin/openai"
	params := url.Values{}
	params.Set("prompt", "login")
	params.Set("ext-oai-did", c.deviceID)
	params.Set("auth_session_logging_id", util.GenerateUUID()) // Assuming util has this or use google/uuid
	params.Set("screen_hint", "login_or_signup")
	params.Set("login_hint", email)

	fullURL := signinURL + "?" + params.Encode()

	formData := url.Values{}
	formData.Set("callbackUrl", baseURL+"/")
	formData.Set("csrfToken", csrf)
	formData.Set("json", "true")

	req, _ := http.NewRequest("POST", fullURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Origin", baseURL)

	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}

	c.log("Signin", resp.StatusCode)
	if data.URL == "" {
		return "", fmt.Errorf("authorize url not found")
	}
	return data.URL, nil
}

// authorize visits the authorize URL and returns the final redirect URL
func (c *Client) authorize(authURL string) (string, error) {
	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	c.log("Authorize", resp.StatusCode)
	return finalURL, nil
}

// register registers the user with email and password
func (c *Client) register(email, password string) (int, map[string]interface{}, error) {
	regURL := authURL + "/api/accounts/user/register"
	payload := map[string]string{
		"username": email,
		"password": password,
	}
	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", regURL, strings.NewReader(string(jsonPayload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", authURL+"/create-account/password")
	req.Header.Set("Origin", authURL)

	// Add trace headers if available in util
	traceHeaders := util.MakeTraceHeaders()
	for k, v := range traceHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	json.Unmarshal(body, &data)

	c.log("Register", resp.StatusCode)
	return resp.StatusCode, data, nil
}

// sendOTP sends the OTP to the user's email
func (c *Client) sendOTP() (int, map[string]interface{}, error) {
	otpURL := authURL + "/api/accounts/email-otp/send"
	req, _ := http.NewRequest("GET", otpURL, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Referer", authURL+"/create-account/password")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		data = map[string]interface{}{"text": string(body)}
	}

	c.log("Send OTP", resp.StatusCode)
	return resp.StatusCode, data, nil
}

// validateOTP validates the OTP code
func (c *Client) validateOTP(code string) (int, map[string]interface{}, error) {
	valURL := authURL + "/api/accounts/email-otp/validate"
	payload := map[string]string{"code": code}
	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", valURL, strings.NewReader(string(jsonPayload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", authURL+"/email-verification")
	req.Header.Set("Origin", authURL)

	traceHeaders := util.MakeTraceHeaders()
	for k, v := range traceHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	json.Unmarshal(body, &data)

	c.log(fmt.Sprintf("Validate OTP [%s]", code), resp.StatusCode)
	return resp.StatusCode, data, nil
}

// createAccount creates the user account with name and birthdate
// NOTE: No sentinel token needed for this step (confirmed from working implementations)
func (c *Client) createAccount(name, birthdate string) (int, map[string]interface{}, error) {
	createURL := authURL + "/api/accounts/create_account"
	payload := map[string]string{
		"name":      name,
		"birthdate": birthdate,
	}
	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", createURL, strings.NewReader(string(jsonPayload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", authURL+"/about-you")
	req.Header.Set("Origin", authURL)

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	json.Unmarshal(body, &data)

	c.log("Create Account", resp.StatusCode)
	return resp.StatusCode, data, nil
}

// callback handles the callback URL
func (c *Client) callback(cbURL string) (int, map[string]interface{}, error) {
	if cbURL == "" {
		return 0, nil, fmt.Errorf("empty callback url")
	}

	req, _ := http.NewRequest("GET", cbURL, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	c.log("Callback", resp.StatusCode)
	return resp.StatusCode, map[string]interface{}{"final_url": resp.Request.URL.String()}, nil
}

func (c *Client) RunRegister(emailAddr, password, name, birthdate string) error {
	c.print("Starting registration flow...")

	if err := c.visitHomepage(); err != nil {
		return err
	}
	c.randomDelay(0.3, 0.8)

	csrf, err := c.getCSRF()
	if err != nil {
		return err
	}
	c.randomDelay(0.2, 0.5)

	authURL, err := c.signin(emailAddr, csrf)
	if err != nil {
		return err
	}
	c.randomDelay(0.3, 0.8)

	finalURL, err := c.authorize(authURL)
	if err != nil {
		return err
	}
	c.randomDelay(0.3, 0.8)

	u, _ := url.Parse(finalURL)
	finalPath := u.Path


	needOTP := false

	if strings.Contains(finalPath, "create-account/password") {
		c.randomDelay(0.5, 1.0)
		status, data, err := c.register(emailAddr, password)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("register failed (%d): %v", status, data)
		}
		c.randomDelay(0.3, 0.8)
		c.sendOTP()
		needOTP = true
	} else if strings.Contains(finalPath, "email-verification") || strings.Contains(finalPath, "email-otp") {
		c.print("Jump to OTP verification stage")
		needOTP = true
	} else if strings.Contains(finalPath, "about-you") {
		c.print("Jump to fill information stage")
		c.randomDelay(0.5, 1.0)
		status, data, err := c.createAccount(name, birthdate)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("create account failed (%d): %v", status, data)
		}
		c.randomDelay(0.3, 0.5)

		var cbURL string
		if u, ok := data["continue_url"].(string); ok {
			cbURL = u
		} else if u, ok := data["url"].(string); ok {
			cbURL = u
		} else if u, ok := data["redirect_url"].(string); ok {
			cbURL = u
		}
		c.callback(cbURL)
		return nil
	} else if strings.Contains(finalPath, "callback") || strings.Contains(finalURL, "chatgpt.com") {
		c.print("Account registration completed")
		return nil
	} else {
		c.print(fmt.Sprintf("Unknown jump: %s", finalURL))
		c.register(emailAddr, password)
		c.sendOTP()
		needOTP = true
	}

	if needOTP {
		otpCode, err := email.GetVerificationCode(emailAddr, 20, 3*time.Second)
		if err != nil {
			return err
		}

		c.randomDelay(0.3, 0.8)
		status, data, err := c.validateOTP(otpCode)
		if err != nil {
			return err
		}

		if status != 200 {
			c.print("Verification code failed, retrying...")
			c.sendOTP()
			c.randomDelay(1.0, 2.0)
			otpCode, err = email.GetVerificationCode(emailAddr, 10, 3*time.Second)
			if err != nil {
				return err
			}
			c.randomDelay(0.3, 0.8)
			status, data, err = c.validateOTP(otpCode)
			if err != nil {
				return err
			}
			if status != 200 {
				return fmt.Errorf("verification code failed after retry (%d): %v", status, data)
			}
		}
	}

	c.randomDelay(0.5, 1.5)
	status, data, err := c.createAccount(name, birthdate)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("create account failed (%d): %v", status, data)
	}

	c.randomDelay(0.2, 0.5)
	var cbURL string
	if u, ok := data["continue_url"].(string); ok {
		cbURL = u
	} else if u, ok := data["url"].(string); ok {
		cbURL = u
	} else if u, ok := data["redirect_url"].(string); ok {
		cbURL = u
	}
	c.callback(cbURL)

	return nil
}

func (c *Client) randomDelay(low, high float64) {
	delay := low + rand.Float64()*(high-low)
	time.Sleep(time.Duration(delay * float64(time.Second)))
}
