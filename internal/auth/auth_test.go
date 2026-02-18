package auth

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExtractAccessTokenFindsPathScopedCookie(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	baseURL := "https://example.com"
	u, _ := url.Parse(baseURL + "/wand2/api/users/current")
	jar.SetCookies(u, []*http.Cookie{
		{
			Name:  "productionaccess_token",
			Value: "abc123",
			Path:  "/wand2",
		},
	})

	token, err := ExtractAccessToken(client, baseURL)
	if err != nil {
		t.Fatalf("extract access token: %v", err)
	}
	if token != "abc123" {
		t.Fatalf("expected token abc123, got %q", token)
	}
}

func TestExtractXSRFTokenFindsAndDecodesPathScopedCookie(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	baseURL := "https://example.com"
	u, _ := url.Parse(baseURL + "/wand/app/worker/index.html")
	jar.SetCookies(u, []*http.Cookie{
		{
			Name:  "X-XSRF-TOKEN",
			Value: "\"tok%2Ben%2F1\"",
			Path:  "/wand",
		},
	})

	token, err := ExtractXSRFToken(client, baseURL)
	if err != nil {
		t.Fatalf("extract xsrf token: %v", err)
	}
	if token != "tok+en/1" {
		t.Fatalf("expected token tok+en/1, got %q", token)
	}
}

func TestLoginReturnsInvalidCredentialsErrorWithoutCurrentUserCall(t *testing.T) {
	var currentUserCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.html":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<span class="red11">Invalid username / password</span>`))
		case "/wand2/api/users/current":
			currentUserCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"userId":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Transport: srv.Client().Transport, Jar: jar}

	authn := &Authenticator{BaseURL: srv.URL, Client: client}
	err = authn.Login(context.Background(), "user@example.com", "bad-password")
	if err == nil {
		t.Fatalf("expected login error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "invalid username or password") {
		t.Fatalf("expected invalid credentials error, got %v", err)
	}
	if currentUserCalls != 0 {
		t.Fatalf("expected current user endpoint to not be called, got %d calls", currentUserCalls)
	}
}

func TestLoginReturnsSessionNotEstablishedErrorWithoutCurrentUserCall(t *testing.T) {
	var currentUserCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.html":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
				<html><body>
				<span>Please log in to your account below</span>
				<form><input name="password_login" /></form>
				</body></html>`))
		case "/wand2/api/users/current":
			currentUserCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"userId":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Transport: srv.Client().Transport, Jar: jar}

	authn := &Authenticator{BaseURL: srv.URL, Client: client}
	err = authn.Login(context.Background(), "user@example.com", "password")
	if err == nil {
		t.Fatalf("expected login error")
	}
	if !strings.Contains(err.Error(), "interactive SSO/MFA") {
		t.Fatalf("expected session not established error, got %v", err)
	}
	if currentUserCalls != 0 {
		t.Fatalf("expected current user endpoint to not be called, got %d calls", currentUserCalls)
	}
}
