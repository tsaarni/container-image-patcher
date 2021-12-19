package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	// Subcommands

	// image-patcher extract-jar source-tag match dest-dir
	extractJarFlags          = flag.NewFlagSet("extract-jar", flag.ExitOnError)
	extractJarFlagsSourceTag = extractJarFlags.String("source-tag", "", "Tag of the image to be scanned")
	extractJarFlagsMatch     = extractJarFlags.String("match", "", "Regex pattern to search for jar files in the image")
	extractJarFlagsDestDir   = extractJarFlags.String("dest-dir", "", "Destination directory where to export the impacted JARs")

	// image-patcher patch source-tag patch-dir dest-tag
	patchFlags          = flag.NewFlagSet("patch", flag.ExitOnError)
	patchFlagsSourceTag = patchFlags.String("source-tag", "", "Tag of the source image to be patched")
	patchFlagsPatchDir  = patchFlags.String("patch-dir", "", "Source directory where to import files to the patch layer")
	patchFlagsDestTag   = patchFlags.String("dest-tag", "", "Tag of the destination image")
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
	case "extract-jar":
		err = extractJarFlags.Parse(args[1:])
		if err != nil {
			break
		}
		ensureNotEmpty(extractJarFlags.Usage, extractJarFlagsSourceTag, extractJarFlagsMatch, extractJarFlagsDestDir)
		err = extractJar(*extractJarFlagsSourceTag, *extractJarFlagsMatch, *extractJarFlagsDestDir)
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
	extractJarFlags.Usage()
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
