package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "jsonlink: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("jsonlink", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: jsonlink [options] [file.json ...]")
		fmt.Fprintln(stderr, "With no file arguments, one JSON document is read from stdin.")
		fmt.Fprintln(stderr, "Each file may contain one object, an object array, or {\"objects\": [...]}.")
		flags.PrintDefaults()
	}

	imagePath := flags.String("o", "", "write the linked binary image to this path (instead of only reporting it)")
	reportPath := flags.String("report", "", "write the JSON report to this path")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	allObjects := make([]Object, 0)
	for _, inputPath := range flags.Args() {
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return err
		}
		objects, err := ParseInput(data, filepath.Base(inputPath))
		if err != nil {
			return fmt.Errorf("%s: %w", inputPath, err)
		}
		allObjects = append(allObjects, objects...)
	}

	if flags.NArg() == 0 {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		objects, err := ParseInput(data, "stdin")
		if err != nil {
			return err
		}
		allObjects = objects
	}

	// Linking must finish and the report must marshal successfully before any
	// output file is created or replaced.
	report, err := Link(allObjects)
	if err != nil {
		return err
	}
	image, err := base64.StdEncoding.DecodeString(report.ImageBase64)
	if err != nil {
		return err
	}

	var encodedReport bytes.Buffer
	encoder := json.NewEncoder(&encodedReport)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return err
	}

	if *imagePath != "" {
		if err := atomicWriteFile(*imagePath, image, 0o666); err != nil {
			return fmt.Errorf("write image: %w", err)
		}
	}
	if *reportPath != "" {
		if err := atomicWriteFile(*reportPath, encodedReport.Bytes(), 0o666); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	if *imagePath == "" && *reportPath == "" {
		if _, err := stdout.Write(encodedReport.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}

	file, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(perm); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
