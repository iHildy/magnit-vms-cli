package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type Authenticator struct {
	BaseURL string
	Client  *http.Client
}

func NewHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Jar:     jar,
		Timeout: 45 * time.Second,
	}, nil
}

func (a *Authenticator) Login(ctx context.Context, username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}

	form := url.Values{}
	form.Set("username", username)
	form.Set("password_login", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.BaseURL, "/")+"/login.html", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "hour-logging-cli/1.0")

	resp, err := a.Client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	if resp.StatusCode >= 400 {
		return fmt.Errorf("login failed with status %d", resp.StatusCode)
	}
	if err := validateLoginResponse(resp, body); err != nil {
		return err
	}

	_, err = a.CurrentUser(ctx)
	if err != nil {
		return fmt.Errorf("login validation failed: %w", err)
	}

	return nil
}

func (a *Authenticator) CurrentUser(ctx context.Context) (map[string]any, error) {
	endpoint := strings.TrimRight(a.BaseURL, "/") + "/wand2/api/users/current?noCache=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build users/current request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if token, err := ExtractAccessToken(a.Client, a.BaseURL); err == nil && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("users/current request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("users/current failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode users/current response: %w", err)
	}
	return out, nil
}

func validateLoginResponse(resp *http.Response, body []byte) error {
	lowerBody := bytes.ToLower(body)
	if bytes.Contains(lowerBody, []byte("invalid username / password")) || bytes.Contains(lowerBody, []byte("invalid username/password")) {
		return fmt.Errorf("invalid username or password")
	}

	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/login.html") &&
			bytes.Contains(lowerBody, []byte("name=\"password_login\"")) &&
			bytes.Contains(lowerBody, []byte("please log in to your account below")) {
			return fmt.Errorf("login did not establish an authenticated session; verify credentials or whether your account requires interactive SSO/MFA")
		}
	}

	return nil
}

func ExtractXSRFToken(client *http.Client, baseURL string) (string, error) {
	cookies, err := collectSessionCookies(client, baseURL)
	if err != nil {
		return "", err
	}

	for _, c := range cookies {
		name := strings.ToLower(c.Name)
		if name == "xsrf-token" || name == "x-xsrf-token" || name == "xsrftoken" || name == "_xsrf" {
			if c.Value != "" {
				val := strings.Trim(c.Value, "\"")
				if decoded, err := url.QueryUnescape(val); err == nil && decoded != "" {
					return decoded, nil
				}
				return val, nil
			}
		}
	}

	return "", fmt.Errorf("xsrf token cookie not found in session")
}

func ExtractAccessToken(client *http.Client, baseURL string) (string, error) {
	cookies, err := collectSessionCookies(client, baseURL)
	if err != nil {
		return "", err
	}

	for _, c := range cookies {
		name := strings.ToLower(c.Name)
		if name == "productionaccess_token" || name == "access_token" {
			if c.Value != "" {
				val := strings.Trim(c.Value, "\"")
				if decoded, err := url.QueryUnescape(val); err == nil && decoded != "" {
					return decoded, nil
				}
				return val, nil
			}
		}
	}

	return "", fmt.Errorf("access token cookie not found in session")
}

func collectSessionCookies(client *http.Client, baseURL string) ([]*http.Cookie, error) {
	if client == nil || client.Jar == nil {
		return nil, fmt.Errorf("http cookie jar is not configured")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}

	var out []*http.Cookie
	seen := make(map[string]struct{})
	for _, cookieURL := range cookieLookupURLs(u) {
		for _, c := range client.Jar.Cookies(cookieURL) {
			if c == nil || c.Name == "" {
				continue
			}
			key := strings.ToLower(c.Name) + "\x00" + c.Value
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func cookieLookupURLs(base *url.URL) []*url.URL {
	paths := []string{
		"/",
		"/wand",
		"/wand/",
		"/wand2",
		"/wand2/",
		"/wand/app/worker/",
		"/wand/app/worker/index.html",
	}

	urls := make([]*url.URL, 0, len(paths))
	for _, path := range paths {
		u := *base
		u.Path = path
		u.RawPath = ""
		u.RawQuery = ""
		u.Fragment = ""
		urls = append(urls, &u)
	}
	return urls
}
