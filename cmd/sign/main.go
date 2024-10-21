package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vaxvhbe/jsonsign"
)

func main() {
	// Declaration of flags (command line parameters)
	privateKeyFilePath := flag.String("priv", "", "Path to the private key file")
	jsonFilePath := flag.String("json", "", "Path to the JSON file")

	// Parse les flags fournis
	flag.Parse()

	// Check that the parameters are supplied correctly
	if *privateKeyFilePath == "" || *jsonFilePath == "" {
		fmt.Println("Usage: program -priv <privateKeyPath> -json <jsonFilePath>")
		os.Exit(1)
	}

	// Initialise JsonSign with key paths
	js := jsonsign.New(
		jsonsign.WithPrivateKeyFilePath(*privateKeyFilePath),
	)

	// Sign the JSON fileZ
	if err := js.Sign(*jsonFilePath); err != nil {
		fmt.Printf("cannot sign json 💥: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("JSON signed successfully 👍")
}
