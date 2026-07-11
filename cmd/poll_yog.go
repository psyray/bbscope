package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sw33tLie/bbscope/v2/internal/utils"
	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	yogplatform "github.com/sw33tLie/bbscope/v2/pkg/platforms/yogosha"
	"github.com/sw33tLie/bbscope/v2/pkg/whttp"
)

// poll yog: shorthand for Yogosha
var pollYogCmd = &cobra.Command{
	Use:   "yog",
	Short: "Poll Yogosha programs",
	RunE: func(cmd *cobra.Command, _ []string) error {
		token, _ := cmd.Flags().GetString("token") // Token is CLI-only, not from config
		email := viper.GetString("yogosha.email")
		password := viper.GetString("yogosha.password")
		otpSecret := viper.GetString("yogosha.otpsecret")
		proxy, _ := rootCmd.Flags().GetString("proxy")
		if proxy != "" {
			whttp.SetupProxy(proxy)
		}
		// Validate auth: require either token OR (email+password+otp-secret)
		if token == "" && (email == "" || password == "" || otpSecret == "") {
			utils.Log.Error("yogosha requires either token or email+password+otp-secret")
			return nil
		}

		poller := &yogplatform.Poller{}
		if err := poller.Authenticate(cmd.Context(), platforms.AuthConfig{Token: token, Email: email, Password: password, OtpSecret: otpSecret, Proxy: proxy}); err != nil {
			return err
		}
		return runPollWithPollers(cmd, []platforms.PlatformPoller{poller})
	},
}

func init() {
	pollCmd.AddCommand(pollYogCmd)
	pollYogCmd.Flags().StringP("token", "t", "", "Yogosha bearer token (optional if using email/password + otp secret)")
	pollYogCmd.Flags().StringP("email", "E", "", "Yogosha login email")
	pollYogCmd.Flags().StringP("password", "P", "", "Yogosha login password")
	pollYogCmd.Flags().StringP("otp-secret", "O", "", "Yogosha TOTP secret (base32)")
	viper.BindPFlag("yogosha.email", pollYogCmd.Flags().Lookup("email"))
	viper.BindPFlag("yogosha.password", pollYogCmd.Flags().Lookup("password"))
	viper.BindPFlag("yogosha.otpsecret", pollYogCmd.Flags().Lookup("otp-secret"))
}
