package main

import "fmt"

// 定义结构体 wt_tools_cmd
type wt_tools_cmd struct {
    Cmd    string   // 用于存储命令
    Short  string   // 用于存储命令的简短描述
    Binary []byte   // 用于存储二进制数据
}

func (cmd wt_tools_cmd)cmd_real_run(argv[] string) {
    fmt.Printf("Command %s\n", cmd.Cmd)
    fmt.Printf("Description: %s\n", cmd.Short)
    fmt.Printf("Binary Data: %v\n", cmd.Binary)
    fmt.Printf("args: %v\n", argv)
}

// 定义一个结构体切片
var wt_tools_cmd_arrays []wt_tools_cmd

func main() {

    // 使用 append 向切片中添加结构体
    wt_tools_cmd_arrays = append(wt_tools_cmd_arrays, wt_tools_cmd{
        Cmd:    "ls",
        Short:  "List directory contents",
        Binary: []byte{0x01, 0x02, 0x03},
    })
    wt_tools_cmd_arrays = append(wt_tools_cmd_arrays, wt_tools_cmd{
        Cmd:    "cp",
        Short:  "Copy files or directories",
        Binary: []byte{0x04, 0x05, 0x06},
    })
    wt_tools_cmd_arrays = append(wt_tools_cmd_arrays, wt_tools_cmd{
        Cmd:    "mv",
        Short:  "Move files or directories",
        Binary: []byte{0x07, 0x08, 0x09},
    })

    // 使用 for range 遍历切片
    for _, cmd := range wt_tools_cmd_arrays {
        cmd.cmd_real_run([]string{"ls", "-al"})
    }
}
