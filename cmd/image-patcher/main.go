package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	// Subcommands

	// image-patcher extract -jar source-tag match dest-dir
	extractFlags          = flag.NewFlagSet("extract", flag.ExitOnError)
	extractFlagsSourceTag = extractFlags.String("source-tag", "", "Tag of the image to be scanned.")
	extractFlagsMatch     = extractFlags.String("match", "", "Regex pattern to search for files in the image.")
	extractFlagsDestDir   = extractFlags.String("dest-dir", "", "Destination directory where to export matching files.")
	extractFlagsJar       = extractFlags.Bool("search-jars", false, "Search for matches inside JARs. Whole JAR is exported if match is found.")

	// image-patcher patch source-tag patch-dir dest-tag
	patchFlags          = flag.NewFlagSet("patch", flag.ExitOnError)
	patchFlagsSourceTag = patchFlags.String("source-tag", "", "Tag of the source image to be patched.")
	patchFlagsPatchDir  = patchFlags.String("patch-dir", "", "Source directory where to import files to the patch layer.")
	patchFlagsDestTag   = patchFlags.String("dest-tag", "", "Tag of the destination image,")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var err error
	switch args[0] {
	case "extract":
		err = extractFlags.Parse(args[1:])
		if err != nil {
			break
		}
		ensureNotEmpty(extractFlags.Usage, extractFlagsSourceTag, extractFlagsMatch, extractFlagsDestDir)
		err = extract(*extractFlagsSourceTag, *extractFlagsMatch, *extractFlagsDestDir, *extractFlagsJar)
	case "patch":
		err = patchFlags.Parse(args[1:])
		if err != nil {
			break
		}
		ensureNotEmpty(patchFlags.Usage, patchFlagsSourceTag, patchFlagsPatchDir, patchFlagsDestTag)
		err = patch(*patchFlagsSourceTag, *patchFlagsPatchDir, *patchFlagsDestTag)
	default:
		flag.Usage()
	}

	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, `image-patcher patches existing container images.
Usage:
  image-patcher command

Commands:

`)
	extractFlags.Usage()
	fmt.Fprintln(w, "")
	patchFlags.Usage()
}

func ensureNotEmpty(usage func(), s ...*string) {
	for _, p := range s {
		if *p == "" {
			fmt.Fprintf(flag.CommandLine.Output(), "Error: mandatory arguments missing\n\n")
			usage()
			os.Exit(2)
		}
	}
}
