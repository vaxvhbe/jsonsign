package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vaxvhbe/jsonsign"
)

func main() {
	// Declaration of flags (command line parameters)
	publicKeyFilePath := flag.String("pub", "", "Path to the public key file")
	jsonFilePath := flag.String("json", "", "Path to the signed JSON file")
	algFlags := jsonsign.SetupAlgFlags()

	// Parse the supplied flags
	flag.Parse()

	alg, err := jsonsign.ParseAlgFlag(algFlags)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Check that the parameters are supplied correctly
	if *publicKeyFilePath == "" || *jsonFilePath == "" {
		fmt.Println("Usage: program -pub <publicKeyPath> -json <jsonFilePath>")
		os.Exit(1)
	}

	// Initialise JsonSign with the public key path
	js := jsonsign.New(
		jsonsign.WithPublicKeyFilePath(*publicKeyFilePath),
	)
	js.Algorithm = *alg

	// Validate the signed JSON file
	if err := js.Validate(*jsonFilePath); err != nil {
		fmt.Printf("cannot validate json 💥: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("JSON validated successfully, signature is valid 👍")
}
