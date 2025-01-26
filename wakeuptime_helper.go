package main

import (
	_ "embed"
	"github.com/spf13/cobra"
)

//go:embed bcc_src/libbpf-tools/wakeuptime
var binary_Bpf_wakeuptime []byte

// 定义子命令
var wakeuptimeCmd = &cobra.Command{
	Use:   "wakeuptime",
	Short: "wakeuptime bsp tools",
	Run: func(cmd *cobra.Command, args []string) {
		RunCommandWithBinary(binary_Bpf_wakeuptime, "bpf_wakeuptime", args)
	},
}


func wakeuptimeHelper(cmd *cobra.Command, args []string) {
	RunCommandWithBinary(binary_Bpf_wakeuptime, "bpf_wakeuptime", []string{"--help"})
}

func init() {
	wakeuptimeCmd.SetHelpFunc(wakeuptimeHelper)
	rootCmd.AddCommand(wakeuptimeCmd)
}