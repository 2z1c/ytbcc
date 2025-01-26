package main

import (
	_ "embed"
	"github.com/spf13/cobra"
)

//go:embed bcc_src/libbpf-tools/helloworld
var binary_Bpf_HelloWorld []byte

// 定义子命令
var helloWorldCmd = &cobra.Command{
	Use:   "hello",
	Short: "Prints a hello message",
	Run: func(cmd *cobra.Command, args []string) {
		RunCommandWithBinary(binary_Bpf_HelloWorld, "bpf_helloworld", []string{})
	},
}


func init(){
	rootCmd.AddCommand(helloWorldCmd)
}
