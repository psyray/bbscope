package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sw33tLie/bbscope/v2/internal/utils"
	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	bbchplatform "github.com/sw33tLie/bbscope/v2/pkg/platforms/bugbountych"
	"github.com/sw33tLie/bbscope/v2/pkg/whttp"
)

// poll bbch: shorthand for BugBounty.ch
var pollBbchCmd = &cobra.Command{
	Use:   "bbch",
	Short: "Poll BugBounty.ch programs",
	RunE: func(cmd *cobra.Command, _ []string) error {
		token, _ := cmd.Flags().GetString("token") // Token is CLI-only, not from config
		email := viper.GetString("bugbountych.email")
		password := viper.GetString("bugbountych.password")
		otpSecret := viper.GetString("bugbountych.otpsecret")
		proxy, _ := rootCmd.Flags().GetString("proxy")
		if proxy != "" {
			whttp.SetupProxy(proxy)
		}
		// Validate auth: require either token OR (email+password+otp-secret)
		if token == "" && (email == "" || password == "" || otpSecret == "") {
			utils.Log.Error("bugbountych requires either token or email+password+otp-secret")
			return nil
		}

		poller := &bbchplatform.Poller{}
		if err := poller.Authenticate(cmd.Context(), platforms.AuthConfig{Token: token, Email: email, Password: password, OtpSecret: otpSecret, Proxy: proxy}); err != nil {
			return err
		}
		return runPollWithPollers(cmd, []platforms.PlatformPoller{poller})
	},
}

func init() {
	pollCmd.AddCommand(pollBbchCmd)
	pollBbchCmd.Flags().StringP("token", "t", "", "BugBounty.ch bearer token (optional if using email/password + otp secret)")
	pollBbchCmd.Flags().StringP("email", "E", "", "BugBounty.ch login email")
	pollBbchCmd.Flags().StringP("password", "P", "", "BugBounty.ch login password")
	pollBbchCmd.Flags().StringP("otp-secret", "O", "", "BugBounty.ch TOTP secret (base32)")
	viper.BindPFlag("bugbountych.email", pollBbchCmd.Flags().Lookup("email"))
	viper.BindPFlag("bugbountych.password", pollBbchCmd.Flags().Lookup("password"))
	viper.BindPFlag("bugbountych.otpsecret", pollBbchCmd.Flags().Lookup("otp-secret"))
}
