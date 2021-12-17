package main

import (
	"archive/tar"
	"bytes"
	"flag"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func main() {
	var source string
	var patchDir string
	var dest string

	flag.StringVar(&source, "source-tag", "", "Tag of the source image to be patched")
	flag.StringVar(&patchDir, "patch-dir", "", "Source directory where to import files to the patch layer")
	flag.StringVar(&dest, "dest-tag", "", "Tag of the destination image")
	flag.Parse()

	log.Println("Opening source image:", source)

	sourceTag, err := name.NewTag(source)
	if err != nil {
		log.Fatal(err)
	}

	destTag, err := name.NewTag(dest)
	if err != nil {
		log.Fatal(err)
	}

	origImage, err := daemon.Image(sourceTag)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Appending patch layer from directory:", patchDir)

	layer, err := createlayer(patchDir)
	if err != nil {
		log.Fatal(err)
	}

	newImage, err := mutate.AppendLayers(origImage, layer)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Writing image with tag:", dest)

	_, err = daemon.Write(destTag, newImage)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Successful")
}

func createlayer(rootdir string) (v1.Layer, error) {
	// Create tar package from files in root directory
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)

	err := filepath.WalkDir(rootdir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			log.Fatal(walkErr)
		}

		relpath, err := filepath.Rel(rootdir, path)
		if err != nil {
			log.Fatal(err)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		hdr := &tar.Header{
			Name: relpath,
			Mode: int64(info.Mode()),
		}

		if d.IsDir() {
			hdr.Typeflag = tar.TypeDir
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
			log.Println("Added file:", relpath)
		}

		err = writer.WriteHeader(hdr)
		if err != nil {
			return err
		}

		if !d.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}

			_, err = io.Copy(writer, f)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return tarball.LayerFromReader(&buf)
}
