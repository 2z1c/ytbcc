package main

import (
	_ "embed"
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "app",                            // 命令的名称
	Short: "A demo application using cobra", // 简短描述
	Long: `This is a demo application built with cobra.
It supports multiple subcommands.`,
}


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



// Execute 启动根命令
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}


func initAddCommand(){
	 rootCmd.AddCommand(helloWorldCmd)
}

func main() {
	initAddCommand()
	Execute()
}