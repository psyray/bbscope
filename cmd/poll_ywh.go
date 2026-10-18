package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sw33tLie/bbscope/v2/internal/utils"
	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	ywhplatform "github.com/sw33tLie/bbscope/v2/pkg/platforms/yeswehack"
	"github.com/sw33tLie/bbscope/v2/pkg/whttp"
)

// poll ywh: shorthand for YesWeHack
var pollYwhCmd = &cobra.Command{
	Use:   "ywh",
	Short: "Poll YesWeHack programs",
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		return bindViperFlags(cmd, map[string]string{
			"yeswehack.email":     "email",
			"yeswehack.password":  "password",
			"yeswehack.otpsecret": "otp-secret",
		})
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		token, _ := cmd.Flags().GetString("token") // Token is CLI-only, not from config
		email := viper.GetString("yeswehack.email")
		password := viper.GetString("yeswehack.password")
		otpSecret := viper.GetString("yeswehack.otpsecret")
		proxy, _ := rootCmd.Flags().GetString("proxy")
		if proxy != "" {
			whttp.SetupProxy(proxy)
		}
		// Auth is optional: the public API serves public programs unauthenticated.
		// A token or email+password+otp-secret is only needed for private programs.
		if token == "" && email == "" && password == "" && otpSecret == "" {
			utils.Log.Info("No YesWeHack credentials provided; polling public programs unauthenticated")
		} else if token == "" && (email == "" || password == "" || otpSecret == "") {
			utils.Log.Error("yeswehack authenticated mode requires either token or email+password+otp-secret")
			return nil
		}

		poller := &ywhplatform.Poller{}
		if err := poller.Authenticate(cmd.Context(), platforms.AuthConfig{Token: token, Email: email, Password: password, OtpSecret: otpSecret, Proxy: proxy}); err != nil {
			return err
		}
		return runPollWithPollers(cmd, []platforms.PlatformPoller{poller})
	},
}

func init() {
	pollCmd.AddCommand(pollYwhCmd)
	pollYwhCmd.Flags().StringP("token", "t", "", "YesWeHack bearer token (optional if using email/password + otp secret)")
	pollYwhCmd.Flags().StringP("email", "E", "", "YesWeHack login email")
	pollYwhCmd.Flags().StringP("password", "P", "", "YesWeHack login password")
	pollYwhCmd.Flags().StringP("otp-secret", "O", "", "YesWeHack TOTP secret (base32)")
}
