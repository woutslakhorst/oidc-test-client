package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"golang.org/x/oauth2"
	"os"

	"beryju.io/oidc-test-client/pkg"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

var Version string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "oidc-test-client",
	Version: Version,
	Short:   "A tool to test various OAuth/OIDC authentication flows",
	Run: func(cmd *cobra.Command, args []string) {
		clientID := os.Getenv("OIDC_CLIENT_ID")
		clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
		provider := os.Getenv("OIDC_PROVIDER")

		// DPoP key provider
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate ECDSA key: %v", err)
		}
		keyProvider := &oauth2.ECKeyProvider{
			Key:   key,
			KeyID: "random-uuid",
		}

		client := pkg.NewOIDCClient(clientID, clientSecret, provider, keyProvider)
		client.Run()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	log.SetLevel(log.DebugLevel)
}
