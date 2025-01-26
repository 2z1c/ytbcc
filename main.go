package main

import "os"
import "fmt"
import "os/exec"
import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "app",                            // 命令的名称
	Short: "A demo application using cobra", // 简短描述
	Long: `This is a demo application built with cobra.
It supports multiple subcommands.`,
}

// 定义子命令
var helloWorldCmd = &cobra.Command{
	Use:   "hello",
	Short: "Prints a hello message",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("hello world")
		exec_cmd := exec.Command("/data/nfs/helloworld")
		exec_cmd.Stdout = os.Stdout
		// 通过 exec.Cmd 中的 Exec 方法来替换当前进程
		err := exec_cmd.Run()  // 执行命令并替换当前进程
		if err != nil {
			fmt.Println("Error executing command:", err)
			os.Exit(1)  // 如果执行失败，退出程序
		}

		// 代码到这里不会被执行，因为当前进程已经被替换
		fmt.Println("This will never be printed")
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