//go:build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/utils"
)

func TestCertificateP12(t *testing.T) {
	setup()
	t.Run("extracted cert and key are equal to p12 inputs", func(t *testing.T) {
		NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate p12 %s %s %s", temp("foo.p12"), temp("foo.crt"), temp("foo.key"))).
			setFlag("no-password", "").
			setFlag("insecure", "").
			run()

		NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate extract %s %s %s", temp("foo.p12"), temp("foo_out.crt"), temp("foo_out.key"))).
			setFlag("no-password", "").
			run()

		foo_crt, _ := pemutil.ReadCertificate(temp("foo.crt"))
		foo_crt_out, _ := pemutil.ReadCertificate(temp("foo_out.crt"))
		assert.Equals(t, foo_crt, foo_crt_out)

		foo_key, _ := utils.ReadFile(temp("foo.key"))
		foo_out_key, _ := utils.ReadFile(temp("foo_out.key"))
		assert.Equals(t, foo_key, foo_out_key)
	})

	t.Run("extracted trust store is equal to p12 input", func(t *testing.T) {
		NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate p12 %s", temp("truststore.p12"))).
			setFlag("ca", temp("intermediate-ca.crt")).
			setFlag("no-password", "").
			setFlag("insecure", "").
			run()

		NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate extract %s", temp("truststore.p12"))).
			setFlag("ca", temp("intermediate-ca_out.crt")).
			setFlag("no-password", "").
			run()

		ca, _ := pemutil.ReadCertificate(temp("intermediate-ca.crt"))
		ca_out, _ := pemutil.ReadCertificate(temp("intermediate-ca_out.crt"))
		assert.Equals(t, ca, ca_out)
	})
}

func setup() {
	NewCLICommand().
		setCommand(fmt.Sprintf("../bin/step certificate create root-ca %s %s", temp("root-ca.crt"), temp("root-ca.key"))).
		setFlag("profile", "root-ca").
		setFlag("no-password", "").
		setFlag("insecure", "").
		run()

	NewCLICommand().
		setCommand(fmt.Sprintf("../bin/step certificate create intermediate-ca %s %s", temp("intermediate-ca.crt"), temp("intermediate-ca.key"))).
		setFlag("profile", "intermediate-ca").
		setFlag("ca", temp("root-ca.crt")).
		setFlag("ca-key", temp("root-ca.key")).
		setFlag("no-password", "").
		setFlag("insecure", "").
		run()

	NewCLICommand().
		setCommand(fmt.Sprintf("../bin/step certificate create foo %s %s", temp("foo.crt"), temp("foo.key"))).
		setFlag("profile", "leaf").
		setFlag("ca", temp("intermediate-ca.crt")).
		setFlag("ca-key", temp("intermediate-ca.key")).
		setFlag("no-password", "").
		setFlag("insecure", "").
		run()
}

func temp(filename string) string {
	return fmt.Sprintf("%s/%s", TempDirectory, filename)
}
