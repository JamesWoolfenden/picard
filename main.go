package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/jameswoolfenden/picard/src/core"
	"github.com/jameswoolfenden/picard/src/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	app := &cli.App{
		Name:                 "picard",
		Usage:                "triage dependency vulnerability alerts: which ones actually reach your code",
		EnableBashCompletion: true,
		Copyright:            "James Woolfenden",
		Commands: []*cli.Command{
			{
				Name:      "version",
				Aliases:   []string{"v"},
				Usage:     "Outputs the application version",
				UsageText: "picard version",
				Action: func(*cli.Context) error {
					fmt.Println(version.Version)

					return nil
				},
			},
			{
				Name:      "scan",
				Aliases:   []string{"s"},
				Usage:     "looks up advisories for a locked project and judges which ones reach it",
				UsageText: "picard scan -d . [--coverage coverage.json] [--format table|json|vex]",
				Flags: append([]cli.Flag{
					&cli.StringFlag{
						Name:    "directory",
						Aliases: []string{"d"},
						Usage:   "project directory",
						Value:   ".",
					},
					&cli.StringFlag{
						Name:  "lock",
						Usage: "lock file (default: the directory's uv.lock, package-lock.json or go.mod)",
					},
					&cli.StringFlag{
						Name:    "coverage",
						Aliases: []string{"c"},
						Usage:   "coverage.py JSON report measured with site-packages included - see README",
					},
					&cli.StringFlag{
						Name:    "format",
						Aliases: []string{"f"},
						Usage:   "output format: table, json or vex (OpenVEX)",
						Value:   "table",
					},
				}, assessFlags...),
				Action: func(c *cli.Context) error {
					opts, err := scanOptions(c)
					if err != nil {
						return err
					}

					report, err := core.Scan(opts)

					var noLock *core.NoLockFileError
					if errors.As(err, &noLock) {
						fmt.Fprintln(os.Stderr, noLock.Error()+" - nothing to scan")

						return nil
					}

					if err != nil {
						return err
					}

					switch c.String("format") {
					case "json":
						return report.WriteJSON(os.Stdout)
					case "vex":
						return report.WriteVEX(os.Stdout, time.Now())
					case "table":
						return report.WriteTable(os.Stdout)
					default:
						return fmt.Errorf("unknown format %q (table, json or vex)", c.String("format"))
					}
				},
			},
			{
				Name:  "dependabot",
				Usage: "checks a repository's Dependabot setup, proposes an action for each alert, and with --apply dismisses the ones that don't reach it",
				UsageText: "picard dependabot -d path/to/checkout [--repo owner/name] [--apply | --apply-judged]\n" +
					"   alerts are matched to picard's verdicts by advisory id; dry run unless --apply\n" +
					"   on a GitLab project (origin, or --repo https://host/group/project) it checks dependency scanning's setup",
				Flags: append([]cli.Flag{
					&cli.StringFlag{Name: "directory", Aliases: []string{"d"}, Usage: "a checkout of the repository", Value: "."},
					&cli.StringFlag{Name: "repo", Usage: "GitHub owner/name, or a GitLab project URL (default: the checkout's origin remote)"},
					&cli.StringFlag{Name: "state", Usage: "alerts to process: open, fixed, dismissed (fixed + --lock replays past alerts)", Value: "open"},
					&cli.StringFlag{Name: "lock", Usage: "use this lock file for every alert instead of the checkout's (replaying past alerts)"},
					&cli.StringFlag{Name: "coverage", Aliases: []string{"c"}, Usage: "coverage.py JSON report for the Python lock"},
					&cli.BoolFlag{Name: "prs", Usage: "also read each open Dependabot PR: which advisories its lock change removes or adds, CI, major bumps"},
					&cli.BoolFlag{Name: "apply", Usage: "dismiss alerts whose verdict rests on facts alone (not shipped)"},
					&cli.BoolFlag{Name: "apply-judged", Usage: "also dismiss alerts whose verdict rests on coverage or a model's assessment"},
					&cli.StringFlag{Name: "format", Aliases: []string{"f"}, Usage: "output format: table or json", Value: "table"},
				}, assessFlags...),
				Action: func(c *cli.Context) error {
					remote, err := dependabotRemote(c)
					if err != nil {
						return err
					}

					if !remote.GitHub() {
						return gitlabSetup(c, remote)
					}

					repo := remote.Path

					opts, err := scanOptions(c)
					if err != nil {
						return err
					}

					gh, err := core.NewGitHub()
					if err != nil {
						return err
					}

					settings, err := core.CheckDependabotSettings(gh, repo, opts.Directory)
					if err != nil {
						return err
					}

					decisions, err := core.PlanDependabot(gh, core.DependabotOptions{
						Repo:      repo,
						Directory: opts.Directory,
						State:     c.String("state"),
						Scan:      opts,
						LockFile:  c.String("lock"),
					})
					if err != nil {
						return err
					}

					// Scorecard's Vulnerabilities alerts are open code-scanning alerts; replaying past
					// Dependabot states has nothing to say about them.
					var scorecard *core.ScorecardPlan

					if c.String("state") == "open" {
						if scorecard, err = core.PlanScorecard(gh, core.DependabotOptions{
							Repo: repo, Directory: opts.Directory, Scan: opts, LockFile: c.String("lock"),
						}); err != nil {
							return err
						}
					}

					var prs []core.PRTriage
					if c.Bool("prs") {
						if prs, err = core.TriagePRs(gh, repo, opts.Directory, settings.PRs, opts); err != nil {
							return err
						}
					}

					var applyErr error
					if c.Bool("apply") || c.Bool("apply-judged") {
						applyErr = core.ApplyDecisions(gh, repo, decisions, c.Bool("apply-judged"))

						if scorecard != nil {
							if err := core.ApplyScorecard(gh, repo, scorecard, c.Bool("apply-judged")); err != nil && applyErr == nil {
								applyErr = err
							}
						}
					}

					switch c.String("format") {
					case "json":
						enc := json.NewEncoder(os.Stdout)
						enc.SetIndent("", "  ")

						if err := enc.Encode(map[string]any{"settings": settings, "alerts": decisions, "scorecard": scorecard, "pull_requests": prs}); err != nil {
							return err
						}
					case "table":
						core.WriteSettings(os.Stdout, repo, settings)

						if err := core.WriteDecisions(os.Stdout, repo, decisions); err != nil {
							return err
						}

						if scorecard != nil {
							core.WriteScorecard(os.Stdout, repo, scorecard)
						}

						if c.Bool("prs") {
							fmt.Println()

							if err := core.WritePRs(os.Stdout, repo, prs); err != nil {
								return err
							}
						}
					default:
						return fmt.Errorf("unknown format %q (table or json)", c.String("format"))
					}

					return applyErr
				},
			},
			{
				Name:      "surface",
				Aliases:   []string{"f"},
				Usage:     "ranks direct dependencies by what each alone brings into the production install",
				UsageText: "picard surface -d . [--coverage coverage.json] [--format table|json]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "directory", Aliases: []string{"d"}, Usage: "project directory", Value: "."},
					&cli.StringFlag{Name: "lock", Usage: "lock file (default: uv.lock, else package-lock.json, else go.mod)"},
					&cli.StringFlag{Name: "coverage", Aliases: []string{"c"}, Usage: "coverage.py JSON report, for functions actually called"},
					&cli.StringFlag{Name: "platform", Usage: "target OS: linux, windows or macos (default: picard.yaml's, else linux)"},
					&cli.StringFlag{Name: "arch", Usage: "target architecture: x86_64 or arm64", Value: "x86_64"},
					&cli.StringFlag{Name: "python", Usage: "target Python, e.g. 3.12 (default: the lock's requires-python minimum)"},
					&cli.BoolFlag{Name: "no-history", Usage: "skip looking up each package's past advisories"},
					&cli.BoolFlag{Name: "detail", Usage: "list the packages of every dependency, not just the bigger ones"},
					&cli.StringFlag{Name: "format", Aliases: []string{"f"}, Usage: "output format: table or json", Value: "table"},
				},
				Action: func(c *cli.Context) error {
					dir := c.String("directory")

					d, err := core.ReadDeployment(filepath.Join(dir, "picard.yaml"))
					if err != nil && !errors.Is(err, fs.ErrNotExist) {
						return err // a picard.yaml that exists but is wrong should not be ignored
					}

					platform := c.String("platform")
					if platform == "" {
						platform = "linux"

						if d != nil && d.Platform != "" {
							platform = d.Platform
						}
					}

					var decisions []core.Decision
					if d != nil {
						decisions = d.Decisions
					}

					report, err := core.AnalyzeProjectSurface(core.SurfaceOptions{
						Directory: dir,
						LockFile:  c.String("lock"),
						Coverage:  c.String("coverage"),
						Target:    core.Target{OS: platform, Arch: c.String("arch"), Python: c.String("python")},
						History:   !c.Bool("no-history"),
						Decisions: decisions,
					})
					if err != nil {
						return err
					}

					switch c.String("format") {
					case "json":
						enc := json.NewEncoder(os.Stdout)
						enc.SetIndent("", "  ")

						return enc.Encode(report)
					case "table":
						return report.WriteTable(os.Stdout, c.Bool("detail"))
					default:
						return fmt.Errorf("unknown format %q (table or json)", c.String("format"))
					}
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("picard failed")
	}
}

// assessFlags are shared by the commands that triage advisories.
var assessFlags = []cli.Flag{
	&cli.BoolFlag{
		Name:    "assess",
		Aliases: []string{"a"},
		Usage:   "have Claude read each shipped package's advisories and fixes (needs ANTHROPIC_API_KEY)",
	},
	&cli.StringFlag{
		Name:  "deployment",
		Usage: "deployment description checked against advisories (default: <directory>/picard.yaml if present)",
	},
	&cli.StringFlag{
		Name:  "model",
		Usage: "model for --assess",
		Value: core.DefaultModel,
	},
	&cli.BoolFlag{
		Name:  "no-exploit-intel",
		Usage: "skip the CISA KEV and EPSS lookups (offline); without them nothing is held back for being exploited",
	},
	&cli.BoolFlag{
		Name:  "no-cache",
		Usage: "re-assess advisories instead of reusing cached assessments",
	},
}

// scanOptions builds triage options from the shared flags.
func scanOptions(c *cli.Context) (core.Options, error) {
	opts := core.Options{
		Directory: c.String("directory"),
		LockFile:  c.String("lock"),
		Coverage:  c.String("coverage"),
	}

	if opts.Coverage != "" && !core.Exists(opts.Coverage) {
		return opts, fmt.Errorf("coverage report %s not found", opts.Coverage)
	}

	deployment := c.String("deployment")
	if deployment == "" && core.Exists(filepath.Join(opts.Directory, "picard.yaml")) {
		deployment = filepath.Join(opts.Directory, "picard.yaml")
	}

	if deployment != "" {
		d, err := core.ReadDeployment(deployment)
		if err != nil {
			return opts, err
		}

		opts.Deployment = d
	}

	if !c.Bool("no-exploit-intel") {
		opts.Intel = core.NewIntel()
	}

	if c.Bool("assess") {
		if opts.Deployment == nil {
			log.Warn().Msg("no picard.yaml deployment description - advisories' preconditions will mostly come out unclear")
		}

		var assessor core.Assessor = core.NewClaudeAssessor(c.String("model"))
		if !c.Bool("no-cache") {
			assessor = &core.CachedAssessor{Inner: assessor, Path: core.DefaultCachePath()}
		}

		opts.Assessor = assessor
	}

	return opts, nil
}

// dependabotRemote is the repository `picard dependabot` works on: --repo (a GitHub
// owner/name, or a URL to any host), else the checkout's origin remote.
func dependabotRemote(c *cli.Context) (core.Remote, error) {
	repo := c.String("repo")
	if repo == "" {
		return core.RemoteFromGit(c.String("directory"))
	}

	if r, ok := core.ParseRemote(repo); ok {
		return r, nil
	}

	return core.Remote{Host: "github.com", Path: repo}, nil
}

// gitlabSetup checks a GitLab project's dependency scanning setup. Reading and dismissing
// alerts is GitHub-only for now, so the flags for that are refused rather than ignored.
func gitlabSetup(c *cli.Context, remote core.Remote) error {
	for _, flag := range []string{"apply", "apply-judged", "prs", "lock"} {
		if c.IsSet(flag) {
			return fmt.Errorf("--%s needs GitHub's Dependabot alerts; %s is a GitLab project", flag, remote.Host)
		}
	}

	gl, err := core.NewGitLab(remote.Host)
	if err != nil {
		return err
	}

	settings, err := core.CheckGitLabSettings(gl, remote.Path, c.String("directory"))
	if err != nil {
		return err
	}

	switch c.String("format") {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(map[string]any{"settings": settings})
	case "table":
		core.WriteGitLabSettings(os.Stdout, remote.Path, settings)
		fmt.Printf("picard doesn't read GitLab's findings yet; `picard scan -d %s` gives its verdicts for this checkout.\n",
			c.String("directory"))

		return nil
	default:
		return fmt.Errorf("unknown format %q (table or json)", c.String("format"))
	}
}
