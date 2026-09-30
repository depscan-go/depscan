package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/D-source1602/depscan/internal/parser"
)

func main() {
	
	path := flag.String("path", ".", "path to the repository to scan")
	flag.Parse()

	fmt.Printf("Scanning: %s\n\n", *path)

	err := filepath.Walk(*path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()

		deps, err := parser.ParseFile(info.Name(), f)
		if err != nil {
			fmt.Printf("  [warn] %s: %v\n", filePath, err)
			return nil
		}

		if deps == nil {
			return nil 
		}

		fmt.Printf("Found %d dependencies in %s:\n", len(deps), filePath)
		for _, d := range deps {
			direct := "  (transitive)"
			if d.Direct {
				direct = "  (direct)    "
			}
			fmt.Printf("  %s  %-50s  %s\n", direct, d.Name, d.Version)
		}
		fmt.Println()

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}