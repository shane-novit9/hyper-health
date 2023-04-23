package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

const addr = "http://localhost:8080"

func main() {
	fmt.Print("Welcome to Hyper-Health, a blockchain solution for electronic health record transactions!\n")
	fmt.Print("\nHere is a list of valid commands:\n")

	command := flag.String("command", "help", "Enter the command you want to perform.")
	flag.Parse()
	fmt.Printf("Command: %s\n", *command)

	if *command == "InitLedger" {
		initLedger()
	}
}

func initLedger() {
	resp, err := http.Get(addr + "/invoke?function=InitLedger")
	if err != nil {
		log.Fatalln(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	sb := string(body)
	fmt.Print(sb)
}
