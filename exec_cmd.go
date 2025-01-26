package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"io/ioutil"
)

// 用来打印管道输出的函数
func printPipe(pipe io.Reader) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		// 打印每行输出
		fmt.Println(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Println("Error reading pipe:", err)
	}
}

func WriteStringToFile(filePath string, data []byte, echo bool) error {
	if echo {
		fmt.Printf(" echo %s > %s", data, filePath)
	}
	err := ioutil.WriteFile(filePath, data, 0644)

	if err != nil {
		fmt.Println(err)
	}

	return nil
}

// write filedata in fileName
func loadScriptsPath(filedata []byte, fileName string) (filePath string, err error) {
	homePath := "/data/"
	defaultPath := path.Join(homePath, ".buildtemp")
	os.MkdirAll(defaultPath, 0755)
	filePath = path.Join(defaultPath, fileName)
	_f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0775)
	if err != nil {
		return "", err
	}

	defer _f.Close()

	_, err = _f.Write(filedata)
	if err != nil {
		return "", err
	}

	return filePath, nil
}


// 执行命令，设置环境变量，并实时打印输出
func RunCommand(cmd string, args []string) error {
	// 创建 exec.Cmd 对象
	command := exec.Command(cmd, args...)

	// 获取标准输出和标准错误的管道
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}

	// 启动命令执行
	if err := command.Start(); err != nil {
		return err
	}

	// 使用 goroutine 实时读取并打印 stdout 和 stderr
	go printPipe(stdout)
	go printPipe(stderr)

	// 等待命令执行完成
	if err := command.Wait(); err != nil {
		return err
	}

	return nil
}

func RunCommandWithBinary(binary []byte,fileName string, args[] string) error {
	binary_path, err:= loadScriptsPath(binary, fileName)

	if err != nil {
		fmt.Println(err)
		return err
	}

	WriteStringToFile("/sys/kernel/debug/mtkfb", []byte("trace:off"), false)
	WriteStringToFile("/sys/kernel/debug/tracing/trace", []byte(""), false)


	return RunCommand(binary_path, args)

}

