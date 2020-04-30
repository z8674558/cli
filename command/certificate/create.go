package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func createCommand() cli.Command {
	return cli.Command{
		Name:   "create",
		Action: command.ActionFunc(createAction),
		Usage:  "create a certificate or certificate signing request",
		UsageText: `**step certificate create** <subject> <crt_file> <key_file>
[**ca**=<issuer-cert>] [**ca-key**=<issuer-key>] [**--csr**]
[**no-password**] [**--profile**=<profile>] [**--san**=<SAN>] [**--bundle**]
[**--kty**=<type>] [**--curve**=<curve>] [**--size**=<size>]`,
		Description: `**step certificate create** generates a certificate or a
certificate signing requests (CSR) that can be signed later using 'step
certificates sign' (or some other tool) to produce a certificate.

This command creates x.509 certificates for use with TLS.

## POSITIONAL ARGUMENTS

<subject>
: The subject of the certificate. Typically this is a hostname for services or an email address for people.

<crt_file>
: File to write CRT or CSR to (PEM format)

<key_file>
: File to write private key to (PEM format)

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Create a CSR and key:

'''
$ step certificate create foo foo.csr foo.key --csr
'''

Create a CSR and key with custom Subject Alternative Names:

'''
$ step certificate create foo foo.csr foo.key --csr \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a CSR and key - do not encrypt the key when writing to disk:

'''
$ step certificate create foo foo.csr foo.key --csr --no-password --insecure
'''

Create a root certificate and key:

'''
$ step certificate create root-ca root-ca.crt root-ca.key --profile root-ca
'''

Create an intermediate certificate and key:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key
'''

Create an intermediate certificate and key with custom Subject Alternative Names:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a leaf certificate and key:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key
'''

Create a leaf certificate and key with custom Subject Alternative Names:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a leaf certificate and key with custom validity:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
  --not-before 24h --not-after 2160h
'''

Create a self-signed leaf certificate and key:

'''
$ step certificate create self-signed-leaf.local leaf.crt leaf.key --profile self-signed --subtle
'''

Create a root certificate and key with underlying OKP Ed25519:

'''
$ step certificate create root-ca root-ca.crt root-ca.key --profile root-ca \
  --kty OKP --curve Ed25519
'''

Create an intermeidate certificate and key with underlying EC P-256 key pair:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key --kty EC --curve P-256
'''

Create a leaf certificate and key with underlying RSA 2048 key pair:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key --kty RSA --size 2048
'''

Create a CSR and key with underlying OKP Ed25519:

'''
$ step certificate create foo foo.csr foo.key --csr --kty OKP --curve Ed25519
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca",
				Usage: `The certificate authority used to issue the new certificate (PEM file).`,
			},
			cli.StringFlag{
				Name:  "ca-key",
				Usage: `The certificate authority private key used to sign the new certificate (PEM file).`,
			},
			cli.BoolFlag{
				Name:  "csr",
				Usage: `Generate a certificate signing request (CSR) instead of a certificate.`,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
			cli.BoolFlag{
				Name: "no-password",
				Usage: `Do not ask for a password to encrypt the private key.
Sensitive key material will be written to disk unencrypted. This is not
recommended. Requires **--insecure** flag.`,
			},
			cli.StringFlag{
				Name:  "profile",
				Value: "leaf",
				Usage: `The certificate profile sets various certificate details such as
  certificate use and expiration. The default profile is 'leaf' which is suitable
  for a client or server using TLS.

: <profile> is a case-sensitive string and must be one of:

    **leaf**
	:  Generate a leaf x.509 certificate suitable for use with TLs.

    **intermediate-ca**
    :  Generate a certificate that can be used to sign additional leaf certificates.

    **root-ca**
    :  Generate a new self-signed root certificate suitable for use as a root CA.

    **self-signed**
    :  Generate a new self-signed leaf certificate suitable for use with TLS.
	This profile requires the **--subtle** flag because the use of self-signed leaf
	certificates is discouraged unless absolutely necessary.`,
			},
			cli.StringFlag{
				Name: "not-before",
				Usage: `The <time|duration> set in the NotBefore property of the certificate. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringFlag{
				Name: "not-after",
				Usage: `The <time|duration> set in the NotAfter property of the certificate. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add DNS or IP Address Subjective Alternative Names (SANs). Use the '--san'
flag multiple times to configure multiple SANs.`,
			},
			cli.BoolFlag{
				Name: "bundle",
				Usage: `Bundle the new leaf certificate with the signing certificate. This flag requires
the **--ca** flag.`,
			},
			flags.KTY,
			flags.Size,
			flags.Curve,
			flags.Force,
			flags.Subtle,
		},
	}
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8
	for i := range bitString {
		b := bitString[len(bitString)-i-1]
		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}
	return 0
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
}

func oidFromExtKeyUsage(eku x509.ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// RFC 5280, 4.2.1.10
type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

type generalSubtree struct {
	Name string `asn1:"tag:2,optional,ia5"`
}

type userExt struct {
	FName string `asn1:"tag:0,optional,ia5"`
	LName string `asn1:"tag:1,optional,ia5"`
}

func createAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "insecure", "no-password")
	}

	subject := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)
	if crtFile == keyFile {
		return errs.EqualArguments(ctx, "CRT_FILE", "KEY_FILE")
	}

	notBefore, ok := flags.ParseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := flags.ParseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}
	if !notAfter.IsZero() && !notBefore.IsZero() && notBefore.After(notAfter) {
		return errs.IncompatibleFlagValues(ctx, "not-before", ctx.String("not-before"), "not-after", ctx.String("not-after"))
	}

	var typ string
	if ctx.Bool("csr") {
		typ = "x509-csr"
	} else {
		typ = "x509"
	}

	kty, crv, size, err := utils.GetKeyDetailsFromCLI(ctx, insecure, "kty", "curve", "size")
	if err != nil {
		return err
	}

	sans := ctx.StringSlice("san")

	var (
		priv       interface{}
		pubPEMs    []*pem.Block
		outputType string
		bundle     = ctx.Bool("bundle")
	)
	switch typ {
	case "x509-csr":
		if bundle {
			return errs.IncompatibleFlagWithFlag(ctx, "bundle", "csr")
		}
		if ctx.IsSet("profile") {
			return errs.IncompatibleFlagWithFlag(ctx, "profile", "csr")
		}
		priv, err = keys.GenerateKey(kty, crv, size)
		if err != nil {
			return errors.WithStack(err)
		}

		if len(sans) == 0 {
			sans = []string{subject}
		}
		dnsNames, ips, emails := x509util.SplitSANs(sans)

		// KeyUsage Extension
		keyUsageExt := pkix.Extension{}
		keyUsageExt.Id = asn1.ObjectIdentifier{2, 5, 29, 15}
		keyUsageExt.Critical = true
		ku := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign
		var a [2]byte
		a[0] = reverseBitsInAByte(byte(ku))
		a[1] = reverseBitsInAByte(byte(ku >> 8))
		l := 1
		if a[1] != 0 {
			l = 2
		}
		bitString := a[:l]
		keyUsageExt.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
		if err != nil {
			return err
		}

		// BasicConstraints Extension
		bcExt := pkix.Extension{}
		bcExt.Id = asn1.ObjectIdentifier{2, 5, 29, 19}
		bcExt.Critical = false
		bcExt.Value, err = asn1.Marshal(basicConstraints{IsCA: true, MaxPathLen: 1})
		if err != nil {
			return err
		}

		// ExtendedKeyUSage Extension
		extKeyUsageExt := pkix.Extension{}
		extKeyUsageExt.Id = asn1.ObjectIdentifier{2, 5, 29, 37}
		extKeyUsageExt.Critical = false
		var oids []asn1.ObjectIdentifier
		var eku []x509.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageMicrosoftKernelCodeSigning,
		}
		for _, u := range eku {
			if oid, ok := oidFromExtKeyUsage(u); ok {
				oids = append(oids, oid)
			} else {
				return err
			}
		}
		// Add unknown extkeyusage
		oids = append(oids, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4})
		extKeyUsageExt.Value, err = asn1.Marshal(oids)
		if err != nil {
			return err
		}

		// NameConstraints Extension
		ncExt := pkix.Extension{}
		ncExt.Id = asn1.ObjectIdentifier{2, 5, 29, 30}
		ncExt.Critical = true
		var out nameConstraints
		permittedDNSDomains := []string{"foo", "bar", "baz"}
		out.Permitted = make([]generalSubtree, len(permittedDNSDomains))
		for i, permitted := range permittedDNSDomains {
			out.Permitted[i] = generalSubtree{Name: permitted}
		}
		ncExt.Value, err = asn1.Marshal(out)
		if err != nil {
			return err
		}

		// Unknown Extension
		uExt := pkix.Extension{}
		uExt.Id = asn1.ObjectIdentifier{1, 2, 3, 4, 5}
		uExt.Critical = false
		uExt.Value = []byte("foo")

		u2Ext := pkix.Extension{}
		u2Ext.Id = asn1.ObjectIdentifier{1, 1, 13, 1, 2, 4, 15, 17, 1, 3, 1, 2, 4, 1}
		u2Ext.Critical = true
		u2Ext.Value, err = asn1.Marshal(userExt{FName: "max", LName: "furman"})
		if err != nil {
			return err
		}

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: subject,
			},
			DNSNames:        dnsNames,
			IPAddresses:     ips,
			EmailAddresses:  emails,
			ExtraExtensions: []pkix.Extension{bcExt, keyUsageExt, extKeyUsageExt, ncExt, uExt, u2Ext},
		}
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
		if err != nil {
			return errors.WithStack(err)
		}

		pubPEMs = []*pem.Block{{
			Type:    "CERTIFICATE REQUEST",
			Bytes:   csrBytes,
			Headers: map[string]string{},
		}}
		outputType = "certificate signing request"
	case "x509":
		var (
			prof      = ctx.String("profile")
			caPath    = ctx.String("ca")
			caKeyPath = ctx.String("ca-key")
			profile   x509util.Profile
		)

		// If the certificate is a leaf certificate (applies to self-signed leaf
		// certs) then make sure it gets a default SAN equivalent to the CN if
		// no other SANs were submitted.
		if (len(sans) == 0) && ((prof == "leaf") || (prof == "self-signed")) {
			sans = []string{subject}
		}
		dnsNames, ips, emails := x509util.SplitSANs(sans)

		if bundle && prof != "leaf" {
			return errs.IncompatibleFlagValue(ctx, "bundle", "profile", prof)
		}
		switch prof {
		case "leaf", "intermediate-ca":
			if caPath == "" {
				return errs.RequiredWithFlagValue(ctx, "profile", prof, "ca")
			}
			if caKeyPath == "" {
				return errs.RequiredWithFlagValue(ctx, "profile", prof, "ca-key")
			}
			switch prof {
			case "leaf":
				var issIdentity *x509util.Identity
				issIdentity, err = loadIssuerIdentity(ctx, prof, caPath, caKeyPath)
				if err != nil {
					return errors.WithStack(err)
				}
				profile, err = x509util.NewLeafProfile(subject, issIdentity.Crt,
					issIdentity.Key, x509util.GenerateKeyPair(kty, crv, size),
					x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
					x509util.WithDNSNames(dnsNames),
					x509util.WithIPAddresses(ips),
					x509util.WithEmailAddresses(emails))
				if err != nil {
					return errors.WithStack(err)
				}
			case "intermediate-ca":
				var issIdentity *x509util.Identity
				issIdentity, err = loadIssuerIdentity(ctx, prof, caPath, caKeyPath)
				if err != nil {
					return errors.WithStack(err)
				}
				profile, err = x509util.NewIntermediateProfile(subject,
					issIdentity.Crt, issIdentity.Key,
					x509util.GenerateKeyPair(kty, crv, size),
					x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
					x509util.WithDNSNames(dnsNames),
					x509util.WithIPAddresses(ips),
					x509util.WithEmailAddresses(emails))
				if err != nil {
					return errors.WithStack(err)
				}
			}
		case "root-ca":
			profile, err = x509util.NewRootProfile(subject,
				x509util.GenerateKeyPair(kty, crv, size),
				x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
				x509util.WithDNSNames(dnsNames),
				x509util.WithIPAddresses(ips),
				x509util.WithEmailAddresses(emails))
			if err != nil {
				return errors.WithStack(err)
			}
		case "self-signed":
			if !ctx.Bool("subtle") {
				return errs.RequiredWithFlagValue(ctx, "profile", "self-signed", "subtle")
			}
			profile, err = x509util.NewSelfSignedLeafProfile(subject,
				x509util.GenerateKeyPair(kty, crv, size),
				x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0),
				x509util.WithDNSNames(dnsNames),
				x509util.WithIPAddresses(ips),
				x509util.WithEmailAddresses(emails))
			if err != nil {
				return errors.WithStack(err)
			}
		default:
			return errs.InvalidFlagValue(ctx, "profile", prof, "leaf, intermediate-ca, root-ca, self-signed")
		}
		var crtBytes []byte
		crtBytes, err = profile.CreateCertificate()
		if err != nil {
			return errors.WithStack(err)
		}
		pubPEMs = []*pem.Block{{
			Type:  "CERTIFICATE",
			Bytes: crtBytes,
		}}
		if bundle {
			pubPEMs = append(pubPEMs, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: profile.Issuer().Raw,
			})
		}
		priv = profile.SubjectPrivateKey()
		outputType = "certificate"
	default:
		return errs.NewError("unexpected type: %s", typ)
	}

	pubBytes := []byte{}
	for _, pp := range pubPEMs {
		pubBytes = append(pubBytes, pem.EncodeToMemory(pp)...)
	}
	if err = utils.WriteFile(crtFile, pubBytes, 0600); err != nil {
		return errs.FileError(err, crtFile)
	}

	if noPass {
		_, err = pemutil.Serialize(priv, pemutil.ToFile(keyFile, 0600))
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		var pass []byte
		pass, err = ui.PromptPassword("Please enter the password to encrypt the private key")
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}
		_, err = pemutil.Serialize(priv, pemutil.WithPassword(pass),
			pemutil.ToFile(keyFile, 0600))
		if err != nil {
			return errors.WithStack(err)
		}
	}

	ui.Printf("Your %s has been saved in %s.\n", outputType, crtFile)
	ui.Printf("Your private key has been saved in %s.\n", keyFile)

	return nil
}

func loadIssuerIdentity(ctx *cli.Context, profile, caPath, caKeyPath string) (*x509util.Identity, error) {
	if caPath == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca")
	}
	if caKeyPath == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca-key")
	}
	return x509util.LoadIdentityFromDisk(caPath, caKeyPath)
}
