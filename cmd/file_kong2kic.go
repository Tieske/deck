package cmd

import (
	"fmt"
	"log"

	"github.com/kong/deck/file"
	"github.com/kong/go-apiops/logbasics"
	"github.com/spf13/cobra"
)

var (
	cmdKong2KicInputFilename  string
	cmdKong2KicOutputFilename string
	cmdKong2KicApi            string
)

// Executes the CLI command "kong2kic"
func executeKong2Kic(cmd *cobra.Command, _ []string) error {

	var (
		outputContent    *file.Content
		err              error
		outputFileFormat file.Format
	)

	verbosity, _ := cmd.Flags().GetInt("verbose")
	logbasics.Initialize(log.LstdFlags, verbosity)

	inputContent, err := file.GetContentFromFiles([]string{cmdKong2KicInputFilename}, false)
	if err != nil {
		return fmt.Errorf("failed reding input file '%s'; %w", cmdKong2KicInputFilename, err)
	}

	outputContent = inputContent.DeepCopy()
	outputFileFormat = file.KIC

	err = file.WriteContentToFile(outputContent, cmdKong2KicOutputFilename, outputFileFormat)

	if err != nil {
		return fmt.Errorf("failed converting Kong to Ingress '%s'; %w", cmdKong2KicInputFilename, err)
	}

	return nil
}

//
//
// Define the CLI data for the openapi2kong command
//
//

func newKong2KicCmd() *cobra.Command {
	kong2KicCmd := &cobra.Command{
		Use:   "kong2kic",
		Short: "Convert Kong configuration files to Kong Ingress Controller (KIC) manifests",
		Long: `Convert Kong configuration files to Kong Ingress Controller (KIC) manifests
		
Currently, only ingress controller manifests are supported. Output format is always YAML.`,
		RunE: executeKong2Kic,
		Args: cobra.NoArgs,
	}

	kong2KicCmd.Flags().StringVarP(&cmdKong2KicInputFilename, "input-file", "i", "-",
		"Kong spec file to process. Use - to read from stdin.")
	kong2KicCmd.Flags().StringVarP(&cmdKong2KicOutputFilename, "output-file", "o", "-",
		"Output file to write. Use - to write to stdout.")
	kong2KicCmd.Flags().StringVarP(&cmdKong2KicApi, "api", "a", "ingress", "[ingress|gateway]")

	return kong2KicCmd
}
