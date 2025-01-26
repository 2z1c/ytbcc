
build:
	# CGO_ENABLED=0 go build -tags netgo -o wttools main.go exec_cmd.go wakeuptime_helper.go
	CGO_ENABLED=0 go build -tags netgo -o wttools main.go exec_cmd.go 