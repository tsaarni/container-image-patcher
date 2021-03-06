package main

import (
	"archive/tar"
	"archive/zip"
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

func extract(image, match, dest string, searchJars bool) error {
	matcher, err := regexp.Compile(match)
	if err != nil {
		return err
	}

	log.Println("Opening image:", image)

	tag, err := name.NewTag(image)
	if err != nil {
		return err
	}

	img, err := daemon.Image(tag)
	if err != nil {
		return err
	}

	// Open the exported image file stream.
	reader, writer := io.Pipe()
	tr := tar.NewReader(reader)

	go func() {
		err = crane.Export(img, writer)
		if err != nil {
			log.Println(err)
		}
	}()

	for {
		// Process next file in the tar package.
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Check if the file matches with the match criteria from user.
		if matcher.MatchString(hdr.Name) {
			log.Println("File matches:", hdr.Name)
			log.Println("Exporting", hdr.Name, "to directory", dest)

			destFile, err := sanitizeExtractPath(dest, hdr.Name)
			if err != nil {
				return err
			}

			// Create directory structure which matches with the directory structure in the source tar file.
			err = os.MkdirAll(path.Dir(destFile), os.ModePerm)
			if err != nil {
				return err
			}

			// Export the matched file.
			w, err := os.Create(destFile)
			if err != nil {
				return err
			}

			_, err = io.Copy(w, tr)
			if err != nil {
				return err
			}
			err = w.Close()
			if err != nil {
				log.Println(err)
			}

			continue
		} else {
			log.Println("Skipping file", hdr.Name)
		}

		if strings.HasSuffix(hdr.Name, ".jar") && searchJars {
			tmpFile, err := os.CreateTemp("", "container-image-patcher.*.jar")
			if err != nil {
				return err
			}

			hasMatch, err := recurseJar(">>>"+hdr.Name+">>>", tr, tmpFile, matcher)
			if err != nil {
				log.Println(err)
			}

			if hasMatch {
				destFile, err := sanitizeExtractPath(dest, hdr.Name)
				if err != nil {
					return err
				}

				log.Println("Exporting impacted JAR", destFile)

				// Create directory structure which matches with the directory structure in the tar file.
				err = os.MkdirAll(path.Dir(destFile), os.ModePerm)
				if err != nil {
					return err
				}

				// Move the jar file from tmp to into the directory structure.
				err = os.Rename(tmpFile.Name(), destFile)
				if err != nil {
					return err
				}
			} else {
				err := os.Remove(tmpFile.Name())
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func recurseJar(logprefix string, reader io.Reader, tmpFile *os.File, matcher *regexp.Regexp) (bool, error) {
	log.Println("Extracting JAR")

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

		// Check if the file matches with the match criteria from user.
		if matcher.MatchString(f.Name) {
			return true, nil
		}

		// Recursively check jar files inside jar files.
		if strings.HasSuffix(f.Name, ".jar") {
			j, err := f.Open()
			if err != nil {
				return false, err
			}

			tmpFile, err := os.CreateTemp("", "container-image-patcher.*.jar")
			if err != nil {
				return false, err
			}
			defer os.Remove(tmpFile.Name())

			hasMatch, err := recurseJar(logprefix+">>>", j, tmpFile, matcher)
			if err != nil {
				return false, err
			}
			if hasMatch {
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
