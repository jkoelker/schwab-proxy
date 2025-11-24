package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/jkoelker/schwab-proxy/admin"
)

const (
	defaultTimeout      = 10 * time.Second
	tabMinWidth         = 2
	tabWidth            = 4
	tabPadding          = 2
	activeFlagConflict  = "--active and --inactive are mutually exclusive"
	noFieldsToUpdateMsg = "no fields provided to update"
)

var (
	errAdminKeyRequired   = errors.New("admin key is required (flag --admin-key or env ADMIN_API_KEY)")
	errActiveFlagConflict = errors.New(activeFlagConflict)
	errNoFieldsToUpdate   = errors.New(noFieldsToUpdateMsg)
	errClientIDRequired   = errors.New("client id is required via --id or positional")
)

// ClientsCommand returns the top-level "clients" command with subcommands.
func ClientsCommand() *cli.Command {
	return &cli.Command{
		Name:  "clients",
		Usage: "Manage OAuth clients via the admin API",
		Flags: clientSharedFlags(),
		Commands: []*cli.Command{
			clientsListCommand(),
			clientsCreateCommand(),
			clientsGetCommand(),
			clientsUpdateCommand(),
			clientsDeleteCommand(),
			clientsRotateSecretCommand(),
		},
	}
}

func clientSharedFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "url",
			Aliases: []string{"u"},
			Usage:   "Base URL of schwab-proxy",
			Sources: cli.EnvVars("SCHWAB_PROXY_URL"),
			Value:   "https://127.0.0.1:8080",
		},
		&cli.StringFlag{
			Name:    "admin-key",
			Usage:   "Admin API key (Bearer)",
			Sources: cli.EnvVars("ADMIN_API_KEY"),
		},
		&cli.BoolFlag{
			Name:    "insecure",
			Usage:   "Skip TLS verification (useful with self-signed certs)",
			Sources: cli.EnvVars("SCHWAB_PROXY_INSECURE"),
		},
		&cli.DurationFlag{
			Name:    "timeout",
			Usage:   "HTTP timeout",
			Sources: cli.EnvVars("SCHWAB_PROXY_TIMEOUT"),
			Value:   defaultTimeout,
		},
	}
}

func clientsListCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List clients",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json", Usage: "Output JSON"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := buildAdminClient(cmd)
			if err != nil {
				return fmt.Errorf("build admin client: %w", err)
			}

			list, err := client.ListClients(ctx)
			if err != nil {
				return fmt.Errorf("list clients: %w", err)
			}

			if cmd.Bool("json") {
				return printJSON(list)
			}

			writer := tabwriter.NewWriter(os.Stdout, tabMinWidth, tabWidth, tabPadding, ' ', 0)
			fmt.Fprintln(writer, "ID\tNAME\tACTIVE\tREDIRECT_URI\tUPDATED_AT")

			for _, cl := range list {
				fmt.Fprintf(writer, "%s\t%s\t%t\t%s\t%s\n", cl.ID, cl.Name, cl.Active, cl.RedirectURI, cl.UpdatedAt)
			}

			return writer.Flush()
		},
	}
}

func clientsCreateCommand() *cli.Command {
	return &cli.Command{
		Name:  "create",
		Usage: "Create a new client",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "Client name", Required: true},
			&cli.StringFlag{
				Name:  "redirect-uri",
				Usage: "Redirect URI",
				Value: "https://127.0.0.1:8182",
			},
			&cli.StringFlag{Name: "description", Usage: "Description"},
			&cli.StringFlag{Name: "scopes", Usage: "Comma-separated scopes"},
			&cli.BoolFlag{Name: "json", Usage: "Output JSON"},
			&cli.BoolFlag{Name: "quiet", Usage: "Print only id and secret"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := buildAdminClient(cmd)
			if err != nil {
				return fmt.Errorf("build admin client: %w", err)
			}

			scopes := parseScopes(cmd.String("scopes"))
			req := admin.CreateClientRequest{
				Name:        cmd.String("name"),
				Description: cmd.String("description"),
				RedirectURI: cmd.String("redirect-uri"),
				Scopes:      scopes,
			}

			resp, err := client.CreateClient(ctx, req)
			if err != nil {
				return fmt.Errorf("create client: %w", err)
			}

			if cmd.Bool("json") {
				return printJSON(resp)
			}

			if cmd.Bool("quiet") {
				fmt.Fprintf(os.Stdout, "%s %s\n", resp.ID, resp.Secret)

				return nil
			}

			fmt.Fprintf(os.Stdout, "ID: %s\nSecret: %s\nName: %s\nRedirect URI: %s\nScopes: %s\nActive: %t\n",
				resp.ID,
				resp.Secret,
				resp.Name,
				resp.RedirectURI,
				strings.Join(resp.Scopes, ","),
				resp.Active,
			)

			return nil
		},
	}
}

func clientsGetCommand() *cli.Command {
	return &cli.Command{
		Name:  "get",
		Usage: "Get a client by ID",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "id", Usage: "Client ID", Required: true},
			&cli.BoolFlag{Name: "json", Usage: "Output JSON"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := buildAdminClient(cmd)
			if err != nil {
				return fmt.Errorf("build admin client: %w", err)
			}

			resp, err := client.GetClient(ctx, cmd.String("id"))
			if err != nil {
				return fmt.Errorf("get client: %w", err)
			}

			if cmd.Bool("json") {
				return printJSON(resp)
			}

			fmt.Fprintf(os.Stdout, "ID: %s\nName: %s\nRedirect URI: %s\nScopes: %s\nActive: %t\nUpdated: %s\n",
				resp.ID,
				resp.Name,
				resp.RedirectURI,
				strings.Join(resp.Scopes, ","),
				resp.Active,
				resp.UpdatedAt,
			)

			return nil
		},
	}
}

func clientsUpdateCommand() *cli.Command {
	return &cli.Command{
		Name:  "update",
		Usage: "Update a client",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "id", Usage: "Client ID", Required: true},
			&cli.StringFlag{Name: "name", Usage: "New name"},
			&cli.StringFlag{Name: "description", Usage: "New description"},
			&cli.StringFlag{Name: "redirect-uri", Usage: "New redirect URI"},
			&cli.StringFlag{Name: "scopes", Usage: "Comma-separated scopes"},
			&cli.BoolFlag{Name: "active", Usage: "Set client active"},
			&cli.BoolFlag{Name: "inactive", Usage: "Set client inactive"},
			&cli.BoolFlag{Name: "json", Usage: "Output JSON"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := buildAdminClient(cmd)
			if err != nil {
				return fmt.Errorf("build admin client: %w", err)
			}

			updates, buildErr := buildUpdateRequest(cmd)
			if buildErr != nil {
				return buildErr
			}

			resp, err := client.UpdateClient(ctx, cmd.String("id"), updates)
			if err != nil {
				return fmt.Errorf("update client: %w", err)
			}

			if cmd.Bool("json") {
				return printJSON(resp)
			}

			fmt.Fprintf(os.Stdout, "Updated client %s (active=%t)\n", resp.ID, resp.Active)

			return nil
		},
	}
}

func clientsDeleteCommand() *cli.Command {
	return &cli.Command{
		Name:  "delete",
		Usage: "Delete a client",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "id", Usage: "Client ID (or pass as positional)"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := buildAdminClient(cmd)
			if err != nil {
				return fmt.Errorf("build admin client: %w", err)
			}

			clientID, err := clientIDFromCmd(cmd)
			if err != nil {
				return fmt.Errorf("client id: %w", err)
			}

			if err := client.DeleteClient(ctx, clientID); err != nil {
				return fmt.Errorf("delete client: %w", err)
			}

			fmt.Fprintf(os.Stdout, "Deleted client %s\n", clientID)

			return nil
		},
	}
}

func clientsRotateSecretCommand() *cli.Command {
	return &cli.Command{
		Name:  "rotate-secret",
		Usage: "Rotate a client's secret and print the new value",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "id", Usage: "Client ID (or pass as positional)"},
			&cli.BoolFlag{Name: "json", Usage: "Output JSON"},
			&cli.BoolFlag{Name: "quiet", Usage: "Print only id and secret"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := buildAdminClient(cmd)
			if err != nil {
				return fmt.Errorf("build admin client: %w", err)
			}

			clientID, err := clientIDFromCmd(cmd)
			if err != nil {
				return fmt.Errorf("client id: %w", err)
			}

			resp, err := client.RotateClientSecret(ctx, clientID)
			if err != nil {
				return fmt.Errorf("rotate client secret: %w", err)
			}

			if cmd.Bool("json") {
				return printJSON(resp)
			}

			if cmd.Bool("quiet") {
				fmt.Fprintf(os.Stdout, "%s %s\n", resp.ID, resp.Secret)

				return nil
			}

			fmt.Fprintf(os.Stdout, "ID: %s\nSecret: %s\nUpdated: %s\n", resp.ID, resp.Secret, resp.UpdatedAt)

			return nil
		},
	}
}

func buildAdminClient(cmd *cli.Command) (*admin.Client, error) {
	key := cmd.String("admin-key")
	if key == "" {
		return nil, errAdminKeyRequired
	}

	cfg := admin.Config{
		BaseURL:  cmd.String("url"),
		APIKey:   key,
		Insecure: cmd.Bool("insecure"),
		Timeout:  cmd.Duration("timeout"),
	}

	client, err := admin.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("init admin client: %w", err)
	}

	return client, nil
}

func clientIDFromCmd(cmd *cli.Command) (string, error) {
	clientID := cmd.String("id")
	if clientID == "" && cmd.Args().Len() > 0 {
		clientID = cmd.Args().First()
	}

	if strings.TrimSpace(clientID) == "" {
		return "", errClientIDRequired
	}

	return clientID, nil
}

func buildUpdateRequest(cmd *cli.Command) (admin.UpdateClientRequest, error) {
	updates := admin.UpdateClientRequest{}

	if v := cmd.String("name"); v != "" {
		updates.Name = &v
	}

	if v := cmd.String("description"); v != "" {
		updates.Description = &v
	}

	if v := cmd.String("redirect-uri"); v != "" {
		updates.RedirectURI = &v
	}

	if v := cmd.String("scopes"); v != "" {
		scopes := parseScopes(v)
		updates.Scopes = &scopes
	}

	if cmd.Bool("active") && cmd.Bool("inactive") {
		return admin.UpdateClientRequest{}, errActiveFlagConflict
	}

	if cmd.Bool("active") {
		val := true
		updates.Active = &val
	}

	if cmd.Bool("inactive") {
		val := false
		updates.Active = &val
	}

	if emptyUpdate(&updates) {
		return admin.UpdateClientRequest{}, errNoFieldsToUpdate
	}

	return updates, nil
}

func parseScopes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")

	scopes := make([]string, 0, len(parts))

	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			scopes = append(scopes, v)
		}
	}

	if len(scopes) == 0 {
		return nil
	}

	return scopes
}

func emptyUpdate(updates *admin.UpdateClientRequest) bool {
	return updates.Name == nil &&
		updates.Description == nil &&
		updates.RedirectURI == nil &&
		updates.Scopes == nil &&
		updates.Active == nil
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	fmt.Fprintln(os.Stdout, string(data))

	return nil
}
