package certificate

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"

	"software.sslmate.com/src/go-pkcs12"
)

func extractCommand() cli.Command {
	return cli.Command{
		Name:   "extract",
		Action: command.ActionFunc(extractAction),
		Usage:  `extract a .p12 file`,
		UsageText: `step certificate extract <p12-path> [<crt-path>] [<key-path>]
[**--ca**=<file>] [**--password-file**=<file>]`,
		Description: `**step certificate extract** extracts a certificate and private key
from a .p12 (PFX / PKCS12) file.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Extract a certificate and a private key from a .p12 file:

'''
$ step certificate extract foo.p12 foo.crt foo.key
'''

Extract a certificate, private key and intermediate certidicates from a .p12 file:

'''
$ step certificate extract foo.p12 foo.crt foo.key --ca intermediate.crt
'''

Extract certificates from "trust store" for Java applications:

'''
$ step certificate extract trust.p12 --ca ca.crt
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "ca",
				Usage: `The path to the <file> containing a CA or intermediate certificate to
add to the .p12 file. Use the '--ca' flag multiple times to add
multiple CAs or intermediates.`,
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to decrypt the .p12 file.`,
			},
			flags.NoPassword,
		},
	}
}

func extractAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 1, 3); err != nil {
		return err
	}

	p12File := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)
	caFile := ctx.String("ca")

	var err error
	var password string
	if passwordFile := ctx.String("password-file"); passwordFile != "" {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	if password == "" && !ctx.Bool("no-password") {
		pass, err := ui.PromptPassword("Please enter a password to decrypt the .p12 file")
		if err != nil {
			return errs.Wrap(err, "error reading password")
		}
		password = string(pass)
	}

	p12Data, err := utils.ReadFile(p12File)
	if err != nil {
		return errs.Wrap(err, "error reading file %s", p12File)
	}

	if crtFile != "" && keyFile != "" {
		// If we have a destination crt path and a key path,
		// we are extracting a .p12 file
		key, crt, CAs, err := pkcs12.DecodeChain(p12Data, password)
		if err != nil {
			return errs.Wrap(err, "failed to decode PKCS12 data")
		}

		_, err = pemutil.Serialize(key, pemutil.ToFile(keyFile, 0600))
		if err != nil {
			return errs.Wrap(err, "failed to serialize private key")
		}

		_, err = pemutil.Serialize(crt, pemutil.ToFile(crtFile, 0600))
		if err != nil {
			return errs.Wrap(err, "failed to serialize certificate")
		}

		if caFile != "" {
			if err := extractCerts(CAs, caFile); err != nil {
				return errs.Wrap(err, "failed to serialize CA certificates")
			}
		}

	} else {
		// If we have only --ca flags,
		// we are extracting from trust store
		certs, err := pkcs12.DecodeTrustStore(p12Data, password)
		if err != nil {
			return errs.Wrap(err, "failed to decode trust store")
		}
		if err := extractCerts(certs, caFile); err != nil {
			return errs.Wrap(err, "failed to serialize CA certificates")
		}
	}

	if crtFile != "" {
		ui.Printf("Your certificate has been saved in %s.\n", crtFile)
	}
	if keyFile != "" {
		ui.Printf("Your private key has been saved in %s.\n", keyFile)
	}
	if caFile != "" {
		ui.Printf("Your CA certificate has been saved in %s.\n", caFile)
	}

	return nil
}

func extractCerts(certs []*x509.Certificate, filename string) error {
	var data []byte
	for _, cert := range certs {
		pemblk, err := pemutil.Serialize(cert)
		if err != nil {
			return err
		}
		data = append(data, pem.EncodeToMemory(pemblk)...)
	}
	if err := utils.WriteFile(filename, data, 0600); err != nil {
		return err
	}
	return nil
}
