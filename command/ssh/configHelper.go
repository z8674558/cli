package ssh

import (
	"encoding/base64"
	"net/http"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"
	"golang.org/x/crypto/ssh"
)

func configHelperCommand() cli.Command {
	return cli.Command{
		Hidden: true,
		Name:   "config-helper",
		Action: command.ActionFunc(configHelperAction),
		Usage:  "configures ssh to be used with certificates",
		UsageText: `**step ssh config-helper**
[**--team**=<name>] [**--host**] [**--set**=<key=value>] [**--set-file**=<file>]
[**--dry-run**] [**--roots**] [**--federation**] [**--force**]
[**--offline**] [**--ca-config**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<string>]`,
		Description: `**step ssh config** configures SSH to be used with certificates. It also supports
flags to inspect the root certificates used to sign the certificates.

This command uses the templates defined in step-certificates to set up user and
hosts environments.

## EXAMPLES

Print the public keys used to verify user certificates:
'''
$ step ssh config-helper --roots
'''

Print the public keys used to verify host certificates:
'''
$ step ssh config-helper --host --roots
'''

Apply configuration templates on the user system:
'''
$ step ssh config-helper
'''

Apply configuration templates on a host:
'''
$ step ssh config-helper --host
'''

Apply configuration templates with custom variables:
'''
$ step ssh config-helper --set User=joe --set Bastion=bastion.example.com
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "host",
				Usage: `Configures a SSH server instead of a client.`,
			},
			flags.Team,
			flags.TeamURL,
			cli.BoolFlag{
				Name:  "roots",
				Usage: `Prints the public keys used to verify user or host certificates.`,
			},
			cli.BoolFlag{
				Name: "federation",
				Usage: `Prints all the public keys in the federation. These keys are used to verify
user or host certificates`,
			},
			cli.StringSliceFlag{
				Name: "set",
				Usage: `The <key=value> used as a variable in the templates. Use the flag multiple
times to set multiple variables.`,
			},
			flags.TemplateSetFile,
			flags.DryRun,
			flags.Force,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.Context,
		},
	}
}

func configHelperAction(ctx *cli.Context) (recoverErr error) {
	team := ctx.String("team")
	isHost := ctx.Bool("host")
	isRoots := ctx.Bool("roots")
	isFederation := ctx.Bool("federation")
	sets := ctx.StringSlice("set")

	switch {
	case team != "" && isHost:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "host")
	case team != "" && isRoots:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "isRoots")
	case team != "" && isFederation:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "federation")
	case team != "" && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "set")
	case isRoots && isFederation:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "federation")
	case isRoots && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "set")
	case isFederation && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "federation", "set")
	}

	// Prepare retry function
	retryFunc, err := loginOnUnauthorized(ctx)
	if err != nil {
		return err
	}

	// Initialize CA client with login if needed.
	client, err := cautils.NewClient(ctx, ca.WithRetryFunc(retryFunc))
	if err != nil {
		return err
	}

	// Prints user or host keys
	if isRoots || isFederation {
		var roots *api.SSHRootsResponse
		if isRoots {
			roots, err = client.SSHRoots()
		} else {
			roots, err = client.SSHFederation()
		}
		if err != nil {
			if e, ok := err.(statusCoder); ok && e.StatusCode() == http.StatusNotFound {
				return errors.New("step certificates is not configured with SSH support")
			}
			return errors.Wrap(err, "error getting ssh public keys")
		}

		var keys []api.SSHPublicKey
		if isHost {
			if len(roots.HostKeys) == 0 {
				return errors.New("step certificates is not configured with an ssh.hostKey")
			}
			keys = roots.HostKeys
		} else {
			if len(roots.UserKeys) == 0 {
				return errors.New("step certificates is not configured with an ssh.userKey")
			}
			keys = roots.UserKeys
		}

		for _, key := range keys {
			ui.Printf("%s %s\n", key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
		}
		return nil
	}

	data := map[string]string{
		"GOOS":     runtime.GOOS,
		"StepPath": step.Path(),
	}
	if len(sets) > 0 {
		for _, s := range sets {
			i := strings.Index(s, "=")
			if i == -1 {
				return errs.InvalidFlagValue(ctx, "set", s, "")
			}
			data[s[:i]] = s[i+1:]
		}
	}

	if !isHost {
		// Try to get the user from a certificate
		if _, ok := data["User"]; !ok {
			agent, err := sshutil.DialAgent()
			if err != nil {
				return err
			}

			var opts []sshutil.AgentOption
			if roots, err := client.SSHRoots(); err == nil && len(roots.UserKeys) > 0 {
				userKeys := make([]ssh.PublicKey, len(roots.UserKeys))
				for i, uk := range roots.UserKeys {
					userKeys[i] = uk.PublicKey
				}
				opts = append(opts, sshutil.WithSignatureKey(userKeys))
			}
			if certs, err := agent.ListCertificates(opts...); err == nil && len(certs) > 0 {
				if p := certs[0].ValidPrincipals; len(p) > 0 {
					data["User"] = p[0]
				}
			}
		}

		// Force a user to have a username
		if _, ok := data["User"]; !ok {
			return errors.New("ssh certificate not found: please run `step ssh login <identity>`")
		}
	}

	// Get configuration snippets and files
	req := &api.SSHConfigRequest{
		Data: data,
	}
	if isHost {
		req.Type = provisioner.SSHHostCert
	} else {
		req.Type = provisioner.SSHUserCert
	}

	resp, err := client.SSHConfig(req)
	if err != nil {
		return err
	}

	var templates []api.Template
	if isHost {
		templates = resp.HostTemplates
	} else {
		templates = resp.UserTemplates
	}
	if len(templates) == 0 {
		ui.Println("No configuration changes were found.")
		return nil
	}

	defer func() {
		if rec := recover(); rec != nil {
			if err, ok := rec.(error); ok {
				recoverErr = err
			} else {
				panic(rec)
			}
		}
	}()

	if ctx.Bool("dry-run") {
		for _, t := range templates {
			ui.Printf("{{ \"%s\" | bold }}\n", step.Abs(t.Path))
			ui.Println(string(t.Content))
		}
		return nil
	}

	for _, t := range templates {
		if err := t.Write(); err != nil {
			return err
		}
		ui.Printf(`{{ "%s" | green }} {{ "%s" | bold }}`+"\n", ui.IconGood, step.Abs(t.Path))
	}

	return nil
}