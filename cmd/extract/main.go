package main

import (
	"archive/tar"
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
)

var matcher = regexp.MustCompile(`log4j-core.+\.jar`)

func main() {
	var image string
	var dest string

	flag.StringVar(&image, "source-tag", "", "Tag of the image to be scanned")
	flag.StringVar(&dest, "dest-dir", "", "Destination directory where to export the impacted JARs")
	flag.Parse()

	log.Println("Opening image:", image)

	tag, err := name.NewTag(image)
	if err != nil {
		log.Fatal(err)
	}

	img, err := daemon.Image(tag)
	if err != nil {
		log.Fatal(err)
	}

	// Open the exported image file stream.
	reader, writer := io.Pipe()
	tr := tar.NewReader(reader)

	go func() {
		err = crane.Export(img, writer)
		if err != nil {
			log.Fatal(err)
		}
	}()

	for {
		// Process next file in the tar package.
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		log.Println(hdr.Name)

		// Check if the file is log4j-core.
		if matcher.MatchString(hdr.Name) {
			log.Println("Impacted JAR found:", hdr.Name)
			log.Println("Exporting impacted JAR", hdr.Name, "to directory", dest)

			destFile, err := sanitizeExtractPath(dest, hdr.Name)
			if err != nil {
				log.Fatal(err)
			}

			// Create directory structure which matches with the directory structure in the tar file.
			err = os.MkdirAll(path.Dir(destFile), os.ModePerm)
			if err != nil {
				log.Fatal(err)
			}

			// Export the jar file.
			w, err := os.Create(destFile)
			if err != nil {
				log.Fatal(err)
			}

			_, err = io.Copy(w, tr)
			if err != nil {
				log.Fatal(err)
			}
			err = w.Close()
			if err != nil {
				log.Println(err)
			}

			continue
		}

		if strings.HasSuffix(hdr.Name, "jar") {
			tmpFile, err := os.CreateTemp("", "container-image-patcher.*.jar")
			if err != nil {
				log.Fatal(err)
			}

			hasLog4j, err := recurseJar(">>>"+hdr.Name+">>>", tr, tmpFile)
			if err != nil {
				log.Println(err)
			}

			if hasLog4j {
				destFile, err := sanitizeExtractPath(dest, hdr.Name)
				if err != nil {
					log.Fatal(err)
				}

				log.Println("Exporting impacted JAR", destFile)

				// Create directory structure which matches with the directory structure in the tar file.
				err = os.MkdirAll(path.Dir(destFile), os.ModePerm)
				if err != nil {
					log.Fatal(err)
				}

				// Move the jar file from tmp to into the directory structure.
				err = os.Rename(tmpFile.Name(), destFile)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				err := os.Remove(tmpFile.Name())
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

func recurseJar(logprefix string, reader io.Reader, tmpFile *os.File) (bool, error) {
	// Copy jar from reader to temp file.
	_, err := io.Copy(tmpFile, reader)
	if err != nil {
		return false, err
	}

	// Open the temp file as zip.
	z, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return false, err
	}
	defer z.Close()

	// Iterate through files in the zip.
	for _, f := range z.File {
		log.Println(logprefix + f.Name)

		// Check if the file is log4j-core.
		if matcher.MatchString(f.Name) {
			return true, nil
		}

		// Recursively check jar files inside jar files.
		if strings.HasSuffix(f.Name, "jar") {
			j, err := f.Open()
			if err != nil {
				return false, err
			}

			tmpFile, err := os.CreateTemp("", "container-image-patcher.*.jar")
			if err != nil {
				return false, err
			}
			defer os.Remove(tmpFile.Name())

			hasLog4j, err := recurseJar(logprefix+">>>", j, tmpFile)
			if err != nil {
				return false, err
			}
			if hasLog4j {
				log.Println("Impacted JAR found:", logprefix+f.Name)
				return true, nil
			}
		}
	}

	return false, nil
}

// Sanitize archive file pathing from "G305: Zip Slip vulnerability"
func sanitizeExtractPath(destination, filePath string) (string, error) {
	dest := filepath.Join(destination, filePath)
	if !strings.HasPrefix(dest, filepath.Clean(destination)+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s: illegal file path", filePath)
	}
	return dest, nil
}
