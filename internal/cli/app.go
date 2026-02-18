package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/ihildy/magnit-vms-cli/internal/api"
	"github.com/ihildy/magnit-vms-cli/internal/auth"
	"github.com/ihildy/magnit-vms-cli/internal/config"
	"github.com/ihildy/magnit-vms-cli/internal/keyring"

	"golang.org/x/term"
)

type App struct {
	Cfg             config.Config
	CfgPath         string
	JSONOutput      bool
	BaseURLOverride string
	Stdout          io.Writer
	Stderr          io.Writer
	Stdin           io.Reader
}

func NewApp() *App {
	return &App{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
	}
}

func (a *App) LoadConfig() error {
	cfg, path, err := config.Load()
	if err != nil {
		return err
	}
	a.Cfg = cfg
	a.CfgPath = path
	return nil
}

func (a *App) SaveConfig() error {
	return config.Save(a.Cfg, a.CfgPath)
}

func (a *App) BaseURL() string {
	if strings.TrimSpace(a.BaseURLOverride) != "" {
		return strings.TrimRight(strings.TrimSpace(a.BaseURLOverride), "/")
	}
	return strings.TrimRight(a.Cfg.BaseURL, "/")
}

func (a *App) NewAuthedClient(ctx context.Context) (*api.Client, map[string]any, *httpContext, error) {
	creds, err := keyring.LoadCredentialsWithStore(a.CredentialStore())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("credentials unavailable, run `magnit auth login` first: %w", err)
	}

	httpClient, err := auth.NewHTTPClient()
	if err != nil {
		return nil, nil, nil, err
	}

	authenticator := &auth.Authenticator{
		BaseURL: a.BaseURL(),
		Client:  httpClient,
	}
	if err := authenticator.Login(ctx, creds.Username, creds.Password); err != nil {
		return nil, nil, nil, fmt.Errorf("login failed using stored credentials: %w", err)
	}

	user, err := authenticator.CurrentUser(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("current user check failed: %w", err)
	}

	client := &api.Client{BaseURL: a.BaseURL(), HTTP: httpClient}
	return client, user, &httpContext{Auth: authenticator}, nil
}

func (a *App) CredentialStore() string {
	if store := strings.TrimSpace(os.Getenv(keyring.CredentialStoreEnvVar)); store != "" {
		return store
	}
	return strings.TrimSpace(a.Cfg.CredentialStore)
}

type httpContext struct {
	Auth *auth.Authenticator
}

func (a *App) IsInteractive() bool {
	stdinFile, stdinOK := a.Stdin.(*os.File)
	stdoutFile, stdoutOK := a.Stdout.(*os.File)
	if !stdinOK || !stdoutOK {
		return false
	}
	return term.IsTerminal(int(stdinFile.Fd())) && term.IsTerminal(int(stdoutFile.Fd()))
}

func (a *App) PromptConfirm(message string) (bool, error) {
	if !a.IsInteractive() {
		return false, errors.New("confirmation required but terminal is non-interactive; use --yes")
	}
	fmt.Fprintf(a.Stderr, "%s [y/N]: ", message)
	reader := bufio.NewReader(a.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func (a *App) ResolveEngagementID(ctx context.Context, client *api.Client, override int64) (int64, error) {
	if override > 0 {
		return override, nil
	}
	if a.Cfg.DefaultEngagementID > 0 {
		return a.Cfg.DefaultEngagementID, nil
	}

	items, err := client.GetEngagementItems(ctx, 0, 200)
	if err != nil {
		return 0, fmt.Errorf("list engagements: %w", err)
	}
	if len(items) == 0 {
		return 0, fmt.Errorf("no engagements returned by API")
	}

	if !a.IsInteractive() {
		return 0, fmt.Errorf("no default engagement configured; set one via `magnit config set-default-engagement --id <id>` or pass --engagement")
	}

	fmt.Fprintln(a.Stderr, "Select engagement:")
	for i, item := range items {
		name := item.BuyerName
		if strings.TrimSpace(name) == "" {
			name = "(unknown buyer)"
		}
		fmt.Fprintf(a.Stderr, "  %d) %d  [%s]  %s\n", i+1, item.ID, item.Status, name)
	}
	fmt.Fprint(a.Stderr, "Enter number: ")
	reader := bufio.NewReader(a.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	line = strings.TrimSpace(line)
	idx, err := strconv.Atoi(line)
	if err != nil || idx < 1 || idx > len(items) {
		return 0, fmt.Errorf("invalid selection")
	}
	return items[idx-1].ID, nil
}
