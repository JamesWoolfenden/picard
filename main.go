package main

import (
	"fmt"
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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "directory",
						Aliases: []string{"d"},
						Usage:   "project directory",
						Value:   ".",
					},
					&cli.StringFlag{
						Name:  "lock",
						Usage: "lock file (default: <directory>/uv.lock)",
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
						Name:  "no-cache",
						Usage: "re-assess advisories instead of reusing cached assessments",
					},
				},
				Action: func(c *cli.Context) error {
					opts := core.Options{
						Directory: c.String("directory"),
						LockFile:  c.String("lock"),
						Coverage:  c.String("coverage"),
					}

					if opts.Coverage != "" && !core.Exists(opts.Coverage) {
						return fmt.Errorf("coverage report %s not found", opts.Coverage)
					}

					deployment := c.String("deployment")
					if deployment == "" && core.Exists(filepath.Join(opts.Directory, "picard.yaml")) {
						deployment = filepath.Join(opts.Directory, "picard.yaml")
					}

					if deployment != "" {
						d, err := core.ReadDeployment(deployment)
						if err != nil {
							return err
						}

						opts.Deployment = d
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

					report, err := core.Scan(opts)
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
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("picard failed")
	}
}
