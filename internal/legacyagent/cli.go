package legacyagent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/buildinfo"
	"github.com/kubebee-com/sre/pkg/cache"
	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/output"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/supportbundle"
	"github.com/kubebee-com/sre/pkg/triage"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type cliScanner interface {
	ScanWithPlan(context.Context, scanplan.Plan) (*scanner.ScanReport, error)
	GetAnalyzers() []scanner.AnalyzerInfo
}

type cliResourceScanner interface {
	cliScanner
	QueryResource(context.Context, string, string, string) (interface{}, error)
	History() scanner.HistoryStore
}

type CLIOptions struct {
	Version             string
	Scanner             cliScanner
	BundleScanner       cliResourceScanner
	Triage              triage.TriageProvider
	RuntimeConfig       *config.Config
	In                  io.Reader
	Out                 io.Writer
	ErrOut              io.Writer
	ConfigPath          string
	LLMHeaders          []string
	ExplainHistoryLimit int
	Serve               func(context.Context) error
	MCPStdio            func(context.Context) error
	SecretValues        []string
}

// rootCommand keeps the small lookup API used by existing callers while the
// embedded Cobra command provides the complete execution surface.
type rootCommand struct {
	*cobra.Command
}

func (command *rootCommand) SetArgs(args []string) {
	command.Command.SetArgs(normalizePlaybookEnabledArgs(args))
}

func (command *rootCommand) Find(args []string) *cobra.Command {
	found, _, _ := command.Command.Find(args)
	return found
}

// NewRootCommand builds a fresh command tree for every invocation. No flag
// variables or mutable command objects are shared between CLI instances.
func NewRootCommand(options CLIOptions) *rootCommand {
	if strings.TrimSpace(options.Version) == "" {
		options.Version = buildinfo.String()
	}
	if options.In == nil {
		options.In = os.Stdin
	}
	if options.Out == nil {
		options.Out = os.Stdout
	}
	if options.ErrOut == nil {
		options.ErrOut = os.Stderr
	}
	if options.ExplainHistoryLimit <= 0 {
		options.ExplainHistoryLimit = 8
	}
	if options.ExplainHistoryLimit > 128 {
		options.ExplainHistoryLimit = 128
	}

	root := &cobra.Command{
		Use:           "sre-agent",
		Short:         "Kubebee Kubernetes SRE agent",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(options.Out)
	root.SetErr(options.ErrOut)
	root.SetIn(options.In)
	root.PersistentFlags().StringVar(&options.ConfigPath, "config", options.ConfigPath, "path to the user configuration file")
	root.PersistentFlags().StringSliceVar(&options.LLMHeaders, "llm-headers", options.LLMHeaders, "custom provider request header in key:value form; repeatable")
	root.PersistentFlags().StringSliceVar(&options.LLMHeaders, "custom-headers", options.LLMHeaders, "alias for --llm-headers")
	registerRuntimeConfigFlags(root, options.RuntimeConfig)

	root.AddCommand(newVersionCommand(options))
	root.AddCommand(newServeCommand(options))
	root.AddCommand(newMCPCommand(options))
	root.AddCommand(newScanCommand(options))
	root.AddCommand(newExplainCommand(options))
	root.AddCommand(newAnalyzersCommand(options))
	root.AddCommand(newDocsCommand(options))
	root.AddCommand(newConfigCommand(options))
	root.AddCommand(newFiltersCommand(options))
	root.AddCommand(newCacheCommand(options))
	root.AddCommand(newSupportBundleCommand(options))
	root.AddCommand(newGenerateCommand(options))
	return &rootCommand{Command: root}
}

func registerRuntimeConfigFlags(root *cobra.Command, cfg *config.Config) {
	if root == nil {
		return
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	flags := root.PersistentFlags()
	flags.StringVar(&cfg.DatabaseURL, "database-url", cfg.DatabaseURL, "PostgreSQL database URL for the optional playbook catalog")
	// Help must not display credentials from the resolved runtime configuration.
	flags.Lookup("database-url").DefValue = ""
	flags.BoolVar(&cfg.PlaybookEnabled, "playbook-enabled", cfg.PlaybookEnabled, "Enable the optional PostgreSQL-backed playbook catalog")
	flags.StringVar(&cfg.PlaybookLearningMode, "playbook-learning-mode", cfg.PlaybookLearningMode, "Playbook learning mode: AUTO_DRAFT, OBSERVE_ONLY, or DISABLED")
	flags.Float64Var(&cfg.PlaybookMinConfidence, "playbook-min-confidence", cfg.PlaybookMinConfidence, "Minimum confidence required for playbook policy decisions")
	flags.StringSliceVar(&cfg.PlaybookAllowedActions, "playbook-allowed-actions", cfg.PlaybookAllowedActions, "playbook action allowlist; comma-separated or repeatable")
	flags.StringSliceVar(&cfg.PlaybookAllowedNamespaces, "playbook-allowed-namespaces", cfg.PlaybookAllowedNamespaces, "playbook namespace allowlist; comma-separated or repeatable")
	flags.StringSliceVar(&cfg.PlaybookAllowedKinds, "playbook-allowed-kinds", cfg.PlaybookAllowedKinds, "playbook resource-kind allowlist; comma-separated or repeatable")
	flags.IntVar(&cfg.PlaybookMaxSourceBytes, "playbook-max-source-bytes", cfg.PlaybookMaxSourceBytes, "Maximum bytes per playbook source considered per operation")
	flags.IntVar(&cfg.PlaybookMaxSourceBytes, "playbook-max-sources", cfg.PlaybookMaxSourceBytes, "Deprecated alias for --playbook-max-source-bytes")
	flags.IntVar(&cfg.PlaybookMaxStepCount, "playbook-max-step-count", cfg.PlaybookMaxStepCount, "Maximum playbook steps considered per operation")
	flags.IntVar(&cfg.PlaybookMaxStepCount, "playbook-max-steps", cfg.PlaybookMaxStepCount, "Deprecated alias for --playbook-max-step-count")
	flags.IntVar(&cfg.PlaybookMaxTotalTextBytes, "playbook-max-total-text-bytes", cfg.PlaybookMaxTotalTextBytes, "Maximum total playbook text bytes considered per operation")
}

func newVersionCommand(options CLIOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print the agent version",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(command.OutOrStdout(), options.Version)
			return err
		},
	}
}

func newServeCommand(options CLIOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "start the HTTP service",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if options.Serve == nil {
				return errors.New("serve is unavailable without an embedded server")
			}
			return options.Serve(command.Context())
		},
	}
}

func newMCPCommand(options CLIOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "serve the read-only MCP protocol over local stdio",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if options.MCPStdio == nil {
				return errors.New("MCP stdio is unavailable without an embedded Kubernetes server")
			}
			return options.MCPStdio(command.Context())
		},
	}
}

func newScanCommand(options CLIOptions) *cobra.Command {
	var (
		filterName        string
		namespace         string
		includeNamespaces []string
		excludeNamespaces []string
		labelSelector     string
		kinds             []string
		names             []string
		analyzers         []string
		concurrency       int
		timeout           time.Duration
		format            string
	)
	command := &cobra.Command{
		Use:   "scan",
		Short: "scan the cluster for actionable findings",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if options.Scanner == nil {
				return errors.New("scanner is unavailable")
			}
			plan, err := loadScanPlan(options.ConfigPath, filterName)
			if err != nil {
				return err
			}
			if namespace != "" {
				includeNamespaces = append(includeNamespaces, namespace)
			}
			if len(includeNamespaces) > 0 {
				plan.IncludeNamespaces = append([]string(nil), includeNamespaces...)
			}
			if len(excludeNamespaces) > 0 {
				plan.ExcludeNamespaces = append([]string(nil), excludeNamespaces...)
			}
			if labelSelector != "" {
				plan.LabelSelector = labelSelector
			}
			if len(kinds) > 0 {
				plan.Kinds = append([]string(nil), kinds...)
			}
			if len(names) > 0 {
				plan.Names = append([]string(nil), names...)
			}
			if len(analyzers) > 0 {
				plan.Analyzers = append([]string(nil), analyzers...)
			}
			if concurrency != 0 {
				plan.MaxConcurrency = concurrency
			}
			if timeout != 0 {
				plan.Timeout = timeout
			}
			known := options.Scanner.GetAnalyzers()
			knownNames := make([]string, 0, len(known))
			for _, info := range known {
				knownNames = append(knownNames, info.Name)
			}
			if err := plan.Validate(knownNames); err != nil {
				return err
			}
			report, err := options.Scanner.ScanWithPlan(command.Context(), plan)
			if err != nil {
				return err
			}
			parsedFormat, err := output.ParseFormat(format)
			if err != nil {
				return err
			}
			return output.Render(command.OutOrStdout(), report, output.Options{
				Format:       parsedFormat,
				SecretValues: cliSecretValues(options),
			})
		},
	}
	flags := command.Flags()
	flags.StringVar(&filterName, "filter", "", "named scan filter from user config")
	flags.StringVarP(&namespace, "namespace", "n", "", "namespace to scan")
	flags.StringSliceVar(&includeNamespaces, "include-namespace", nil, "included namespace; repeatable")
	flags.StringSliceVar(&excludeNamespaces, "exclude-namespace", nil, "excluded namespace; repeatable")
	flags.StringVar(&labelSelector, "label-selector", "", "Kubernetes label selector")
	flags.StringSliceVar(&kinds, "kind", nil, "resource kind; repeatable")
	flags.StringSliceVar(&names, "name", nil, "resource name; repeatable")
	flags.StringSliceVar(&analyzers, "analyzer", nil, "analyzer name; repeatable")
	flags.IntVar(&concurrency, "concurrency", 0, "maximum concurrent analyzers")
	flags.DurationVar(&timeout, "timeout", 0, "maximum scan duration")
	flags.StringVarP(&format, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")
	return command
}

func newExplainCommand(options CLIOptions) *cobra.Command {
	var (
		interactive bool
		noCache     bool
	)
	command := &cobra.Command{
		Use:   "explain [question]",
		Short: "ask the configured triage provider a question",
		RunE: func(command *cobra.Command, args []string) error {
			if options.Triage == nil {
				return errors.New("triage provider is unavailable")
			}
			requestContext := command.Context()
			if noCache {
				requestContext = triage.WithCacheBypass(requestContext)
			}
			if interactive || len(args) == 0 {
				return runInteractiveExplain(requestContext, command, options)
			}
			query := sanitizer.RedactorForSecrets(cliSecretValues(options)...).SanitizeText(strings.Join(args, " "))
			reply, err := options.Triage.Explain(requestContext, query, nil)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(command.OutOrStdout(), sanitizer.RedactorForSecrets(cliSecretValues(options)...).SanitizeText(reply))
			return err
		},
	}
	command.Flags().BoolVar(&interactive, "interactive", false, "read questions until :quit")
	command.Flags().BoolVar(&noCache, "no-cache", false, "bypass provider-result cache for this request")
	return command
}

func runInteractiveExplain(ctx context.Context, command *cobra.Command, options CLIOptions) error {
	reader := bufio.NewScanner(options.In)
	reader.Buffer(make([]byte, 1024), 256*1024)
	redactor := sanitizer.RedactorForSecrets(cliSecretValues(options)...)
	history := make([]string, 0, options.ExplainHistoryLimit)
	for reader.Scan() {
		message := strings.TrimSpace(reader.Text())
		if message == ":quit" || message == ":q" || strings.EqualFold(message, "exit") {
			break
		}
		if message == "" {
			continue
		}
		message = redactor.SanitizeText(message)
		query := message
		if len(history) > 0 {
			query = "<UNTRUSTED_CHAT_HISTORY>\n" + strings.Join(history, "\n") + "\n</UNTRUSTED_CHAT_HISTORY>\nCurrent user message: " + message
		}
		reply, err := options.Triage.Explain(ctx, query, nil)
		if err != nil {
			return err
		}
		reply = redactor.SanitizeText(reply)
		if _, err := fmt.Fprintln(command.OutOrStdout(), reply); err != nil {
			return err
		}
		history = append(history, "user: "+message, "assistant: "+reply)
		if len(history) > options.ExplainHistoryLimit {
			history = history[len(history)-options.ExplainHistoryLimit:]
		}
	}
	return reader.Err()
}

func newAnalyzersCommand(options CLIOptions) *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "analyzers",
		Short: "list registered analyzers",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if options.Scanner == nil {
				return errors.New("scanner is unavailable")
			}
			parsed, err := output.ParseFormat(format)
			if err != nil {
				return err
			}
			return writeStructured(command.OutOrStdout(), map[string]interface{}{
				"schema_version": "analyzers/v1",
				"analyzers":      options.Scanner.GetAnalyzers(),
			}, parsed, cliSecretValues(options))
		},
	}
	command.Flags().StringVarP(&format, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")
	return command
}

func newDocsCommand(options CLIOptions) *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "docs [analyzer]",
		Short: "list registered Kubernetes analyzer documentation links",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			source := options.Scanner
			if source == nil {
				// Analyzer metadata is static and can be listed without a cluster
				// connection. Dynamic integrations appear only in a live scanner.
				source = scanner.NewClusterScanner(nil)
			}
			requested := ""
			if len(args) == 1 {
				requested = strings.TrimSpace(args[0])
			}
			entries := make([]map[string]string, 0)
			for _, info := range source.GetAnalyzers() {
				if requested != "" && !strings.EqualFold(requested, info.Name) && !strings.EqualFold(requested, info.Resource) {
					continue
				}
				url := sanitizer.DefaultRedactor().SanitizeURL(info.DocsURL)
				if !isHTTPSURL(url) {
					continue
				}
				entries = append(entries, map[string]string{
					"analyzer": info.Name,
					"resource": info.Resource,
					"title":    info.Description,
					"url":      url,
				})
			}
			if requested != "" && len(entries) == 0 {
				return fmt.Errorf("analyzer documentation %q was not found", requested)
			}
			parsed, err := output.ParseFormat(format)
			if err != nil {
				return err
			}
			return writeStructured(command.OutOrStdout(), map[string]interface{}{
				"schema_version": "docs/v1",
				"entries":        entries,
			}, parsed, cliSecretValues(options))
		},
	}
	command.Flags().StringVarP(&format, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")
	return command
}

func newGenerateCommand(_ CLIOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "generate [provider]",
		Short: "print an allowlisted provider key-help URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			url, ok := supportbundle.ProviderKeyHelpURL(args[0])
			if !ok {
				return fmt.Errorf("provider %q does not have an allowlisted key-help URL", args[0])
			}
			_, err := fmt.Fprintln(command.OutOrStdout(), url)
			return err
		},
	}
}

func newSupportBundleCommand(options CLIOptions) *cobra.Command {
	var resourceSpecs []string
	command := &cobra.Command{
		Use:     "support-bundle [path]",
		Aliases: []string{"dump"},
		Short:   "write a bounded, sanitized diagnostic archive",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if options.BundleScanner == nil {
				return errors.New("support bundle requires a Kubernetes scanner")
			}
			plan, err := loadScanPlan(options.ConfigPath, "")
			if err != nil {
				return err
			}
			report, err := options.BundleScanner.ScanWithPlan(command.Context(), plan)
			if err != nil {
				return err
			}
			resources := make([]supportbundle.ResourcePayload, 0, len(resourceSpecs))
			for _, spec := range resourceSpecs {
				kind, namespace, name, err := parseBundleResourceSpec(spec)
				if err != nil {
					return err
				}
				resource, err := options.BundleScanner.QueryResource(command.Context(), kind, namespace, name)
				if err != nil {
					return fmt.Errorf("query %s/%s: %w", kind, name, err)
				}
				safeResource, err := scanner.SanitizeResourceForKind(kind, resource, sanitizer.RedactorForSecrets(cliSecretValues(options)...))
				if err != nil {
					return err
				}
				encoded, err := json.Marshal(safeResource)
				if err != nil {
					return fmt.Errorf("encode %s/%s: %w", kind, name, err)
				}
				resources = append(resources, supportbundle.ResourcePayload{Kind: kind, Namespace: namespace, Name: name, Data: encoded})
			}
			var history []scanner.HistoryEntry
			if store := options.BundleScanner.History(); store != nil {
				history, err = store.List()
				if err != nil {
					return fmt.Errorf("read scan history: %w", err)
				}
			}
			analyzers := make([]scanner.AnalyzerRun, 0, len(options.BundleScanner.GetAnalyzers()))
			for _, info := range options.BundleScanner.GetAnalyzers() {
				analyzers = append(analyzers, scanner.AnalyzerRun{Info: info})
			}
			path := "sre-support-bundle.zip"
			if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
				path = args[0]
			}
			return supportbundle.Create(path, supportbundle.Input{
				Issues:       report.Issues,
				Analyzers:    analyzers,
				History:      history,
				Resources:    resources,
				SecretValues: cliSecretValues(options),
			}, supportbundle.Options{IncludeResources: len(resources) > 0})
		},
	}
	command.Flags().StringSliceVar(&resourceSpecs, "include-resource", nil, "explicit resource as kind/name or kind/namespace/name")
	return command
}

func parseBundleResourceSpec(value string) (string, string, string, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) == 2 {
		if parts[0] == "" || parts[1] == "" {
			return "", "", "", errors.New("resource must be kind/name")
		}
		return parts[0], "", parts[1], nil
	}
	if len(parts) == 3 && parts[0] != "" && parts[2] != "" {
		return parts[0], parts[1], parts[2], nil
	}
	return "", "", "", errors.New("resource must be kind/name or kind/namespace/name")
}

func newConfigCommand(options CLIOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "config",
		Short: "manage safe user configuration",
		RunE: func(command *cobra.Command, _ []string) error {
			return showConfig(command, options)
		},
	}
	var format string
	show := &cobra.Command{
		Use:   "show",
		Short: "show non-secret configuration",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return showConfigWithFormat(command, options, format)
		},
	}
	show.Flags().StringVarP(&format, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")
	command.AddCommand(show, newConfigProfileCommand(options), newConfigFilterCommand(options))
	return command
}

func showConfig(command *cobra.Command, options CLIOptions) error {
	return showConfigWithFormat(command, options, string(output.FormatJSON))
}

func showConfigWithFormat(command *cobra.Command, options CLIOptions, format string) error {
	store, err := config.NewStore(options.ConfigPath)
	if err != nil {
		return err
	}
	userConfig, err := store.Load()
	if err != nil {
		return err
	}
	parsed, err := output.ParseFormat(format)
	if err != nil {
		return err
	}
	return writeStructured(command.OutOrStdout(), userConfig, parsed, cliSecretValues(options))
}

func newFiltersCommand(options CLIOptions) *cobra.Command {
	return newFilterCommands(options, "filters")
}

func newConfigFilterCommand(options CLIOptions) *cobra.Command {
	return newFilterCommands(options, "filters")
}

func newFilterCommands(options CLIOptions, use string) *cobra.Command {
	command := &cobra.Command{Use: use, Short: "manage named scan filters"}
	var format string
	list := &cobra.Command{
		Use: "list", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			store, err := config.NewStore(options.ConfigPath)
			if err != nil {
				return err
			}
			filters, err := store.ListFilters()
			if err != nil {
				return err
			}
			parsed, err := output.ParseFormat(format)
			if err != nil {
				return err
			}
			return writeStructured(command.OutOrStdout(), filters, parsed, cliSecretValues(options))
		},
	}
	list.Flags().StringVarP(&format, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")
	var name, include, exclude, selector, kinds, names, analyzers string
	add := &cobra.Command{
		Use: "add", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			store, err := config.NewStore(options.ConfigPath)
			if err != nil {
				return err
			}
			return store.CreateFilter(config.AnalyzerFilter{Name: name, IncludeNamespaces: csv(include), ExcludeNamespaces: csv(exclude), LabelSelector: selector, Kinds: csv(kinds), Names: csv(names), Analyzers: csv(analyzers)})
		},
	}
	add.Flags().StringVar(&name, "name", "", "filter name")
	add.Flags().StringVar(&include, "include-namespaces", "", "comma-separated included namespaces")
	add.Flags().StringVar(&exclude, "exclude-namespaces", "", "comma-separated excluded namespaces")
	add.Flags().StringVar(&selector, "label-selector", "", "Kubernetes label selector")
	add.Flags().StringVar(&kinds, "kinds", "", "comma-separated resource kinds")
	add.Flags().StringVar(&names, "names", "", "comma-separated resource names")
	add.Flags().StringVar(&analyzers, "analyzers", "", "comma-separated analyzer names")
	var deleteName, defaultName string
	remove := &cobra.Command{Use: "delete", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		store, err := config.NewStore(options.ConfigPath)
		if err != nil {
			return err
		}
		return store.DeleteFilter(deleteName)
	}}
	remove.Flags().StringVar(&deleteName, "name", "", "filter name")
	setDefault := &cobra.Command{Use: "default", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		store, err := config.NewStore(options.ConfigPath)
		if err != nil {
			return err
		}
		return store.SetDefaultFilter(defaultName)
	}}
	setDefault.Flags().StringVar(&defaultName, "name", "", "filter name")
	command.AddCommand(list, add, remove, setDefault)
	return command
}

func newConfigProfileCommand(options CLIOptions) *cobra.Command {
	command := &cobra.Command{Use: "profile", Short: "manage provider profiles"}
	var format string
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		store, err := config.NewStore(options.ConfigPath)
		if err != nil {
			return err
		}
		profiles, err := store.ListProfiles()
		if err != nil {
			return err
		}
		parsed, err := output.ParseFormat(format)
		if err != nil {
			return err
		}
		return writeStructured(command.OutOrStdout(), profiles, parsed, cliSecretValues(options))
	}}
	list.Flags().StringVarP(&format, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")
	var name, provider, mode, model, baseURL, proxy string
	add := &cobra.Command{Use: "add", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		store, err := config.NewStore(options.ConfigPath)
		if err != nil {
			return err
		}
		return store.CreateProfile(config.ProviderProfile{Name: name, Provider: provider, Mode: mode, Model: model, BaseURL: baseURL, ProxyURL: proxy})
	}}
	add.Flags().StringVar(&name, "name", "", "profile name")
	add.Flags().StringVar(&provider, "provider", "rule", "provider name")
	add.Flags().StringVar(&mode, "mode", "", "provider mode: remote, local, rule, noop, or aws")
	add.Flags().StringVar(&model, "model", "", "model name")
	add.Flags().StringVar(&baseURL, "base-url", "", "provider base URL")
	add.Flags().StringVar(&proxy, "proxy-url", "", "provider proxy URL")
	var deleteName, defaultName string
	remove := &cobra.Command{Use: "delete", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		store, err := config.NewStore(options.ConfigPath)
		if err != nil {
			return err
		}
		return store.DeleteProfile(deleteName)
	}}
	remove.Flags().StringVar(&deleteName, "name", "", "profile name")
	setDefault := &cobra.Command{Use: "default", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		store, err := config.NewStore(options.ConfigPath)
		if err != nil {
			return err
		}
		return store.SetDefaultProfile(defaultName)
	}}
	setDefault.Flags().StringVar(&defaultName, "name", "", "profile name")
	command.AddCommand(list, add, remove, setDefault)
	return command
}

const cliCacheSchemaVersion = "cache/v1"

func newCacheCommand(options CLIOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "cache",
		Short: "inspect and manage the opt-in encrypted provider-result cache",
		Args:  cobra.NoArgs,
	}

	var listFormat, statsFormat string
	list := &cobra.Command{
		Use:   "list",
		Short: "list bounded, non-secret cache entry metadata",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			resultCache, err := openCLIConfiguredCache()
			if err != nil {
				return err
			}
			entries, err := resultCache.List(command.Context())
			if err != nil {
				return fmt.Errorf("list cache entries: %w", err)
			}
			format, err := parseCLIFormat(listFormat)
			if err != nil {
				return err
			}
			return writeStructured(command.OutOrStdout(), map[string]interface{}{
				"schema_version": cliCacheSchemaVersion,
				"entry_count":    len(entries),
				"entries":        entries,
			}, format, cliSecretValues(options))
		},
	}
	list.Flags().StringVarP(&listFormat, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")

	stats := &cobra.Command{
		Use:   "stats",
		Short: "show process-local cache operation counters",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			resultCache, err := openCLIConfiguredCache()
			if err != nil {
				return err
			}
			format, err := parseCLIFormat(statsFormat)
			if err != nil {
				return err
			}
			return writeStructured(command.OutOrStdout(), map[string]interface{}{
				"schema_version": cliCacheSchemaVersion,
				"stats":          resultCache.Stats(),
			}, format, cliSecretValues(options))
		},
	}
	stats.Flags().StringVarP(&statsFormat, "output", "o", string(output.FormatJSON), "output format: json, table, yaml, raw")

	var digestFlag string
	remove := &cobra.Command{
		Use:   "remove <digest>",
		Short: "remove one cache entry by its digest",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 || (len(args) == 0 && strings.TrimSpace(digestFlag) == "") {
				return errors.New("cache remove requires one entry digest")
			}
			if len(args) == 1 && strings.TrimSpace(digestFlag) != "" {
				return errors.New("cache remove accepts a digest either as an argument or with --digest, not both")
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			digest := digestFlag
			if len(args) == 1 {
				digest = args[0]
			}
			if !isCacheDigest(digest) {
				return errors.New("cache entry digest must be 64 lowercase hexadecimal characters")
			}
			digest = strings.TrimSpace(digest)
			resultCache, err := openCLIConfiguredCache()
			if err != nil {
				return err
			}
			entries, err := resultCache.List(command.Context())
			if err != nil {
				return fmt.Errorf("find cache entry: %w", err)
			}
			for _, entry := range entries {
				if entry.Digest != digest {
					continue
				}
				if err := resultCache.Remove(command.Context(), entry.Key); err != nil {
					return fmt.Errorf("remove cache entry: %w", err)
				}
				return nil
			}
			return errors.New("cache entry was not found")
		},
	}
	remove.Flags().StringVar(&digestFlag, "digest", "", "entry digest from cache list output")

	purge := &cobra.Command{
		Use:   "purge",
		Short: "purge all cache entries",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			resultCache, err := openCLIConfiguredCache()
			if err != nil {
				return err
			}
			if err := resultCache.Purge(command.Context()); err != nil {
				return fmt.Errorf("purge cache entries: %w", err)
			}
			return nil
		},
	}

	command.AddCommand(list, stats, remove, purge)
	return command
}

func openCLIConfiguredCache() (*cache.FileCache, error) {
	directory, directorySet := os.LookupEnv("SRE_CACHE_DIR")
	key, keySet := os.LookupEnv("SRE_CACHE_ENCRYPTION_KEY")
	directory = strings.TrimSpace(directory)
	key = strings.TrimSpace(key)
	if !directorySet || !keySet || directory == "" || key == "" {
		return nil, errors.New("SRE_CACHE_DIR and SRE_CACHE_ENCRYPTION_KEY must both be configured to use cache commands")
	}

	settings := config.LoadConfigArgs(nil)
	resultCache, err := cache.NewFileCache(directory, []byte(key),
		cache.WithDefaultTTL(settings.CacheTTL),
		cache.WithMaxEntries(settings.CacheMaxEntries),
		cache.WithMaxValueBytes(settings.CacheMaxValueBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize encrypted cache: %w", err)
	}
	return resultCache, nil
}

func parseCLIFormat(value string) (output.Format, error) {
	format, err := output.ParseFormat(value)
	if err != nil {
		return "", errors.New("unsupported cache output format")
	}
	return format, nil
}

func isCacheDigest(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func isHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && !strings.ContainsAny(value, "\r\n\x00")
}

func loadScanPlan(path, filterName string) (scanplan.Plan, error) {
	resolved, userConfig, err := config.ResolveConfig(config.ResolveOptions{Path: path, FilterName: filterName})
	if err != nil {
		return scanplan.Plan{}, err
	}
	name := strings.TrimSpace(filterName)
	if name == "" {
		name = userConfig.DefaultFilter
	}
	for _, filter := range userConfig.Filters {
		if strings.EqualFold(filter.Name, name) {
			return filter.Plan(), nil
		}
	}
	if name != "" {
		return scanplan.Plan{}, fmt.Errorf("analyzer filter %q not found", name)
	}
	return resolved.ScanPlan(), nil
}

func writeStructured(writer io.Writer, value interface{}, format output.Format, secrets []string) error {
	redactor := sanitizer.RedactorForSecrets(secrets...)
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = []byte(redactor.SanitizeJSON(string(encoded)))
	switch format {
	case output.FormatTable:
		_, err = writer.Write(encoded)
		if err == nil {
			_, err = io.WriteString(writer, "\n")
		}
		return err
	case output.FormatYAML:
		var decoded interface{}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return err
		}
		return yaml.NewEncoder(writer).Encode(decoded)
	case output.FormatRaw:
		_, err = writer.Write(encoded)
		return err
	default:
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, encoded, "", "  "); err != nil {
			return err
		}
		pretty.WriteByte('\n')
		_, err = io.WriteString(writer, pretty.String())
		return err
	}
}

func csv(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func cliSecretValues(options CLIOptions) []string {
	values := append([]string(nil), options.SecretValues...)
	for _, key := range []string{"LLM_API_KEY", "SRE_LLM_API_KEY", "SRE_API_TOKEN", "API_TOKEN", "WEBHOOK_URL", "SRE_CACHE_ENCRYPTION_KEY", "SRE_DATABASE_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			values = append(values, value)
		}
	}
	return values
}
