package main

import (
	"archive/tar"
	"bytes"
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

func patch(source, patchDir, dest string) error {
	log.Println("Opening source image:", source)

	sourceTag, err := name.NewTag(source)
	if err != nil {
		return err
	}

	destTag, err := name.NewTag(dest)
	if err != nil {
		return err
	}

	origImage, err := daemon.Image(sourceTag)
	if err != nil {
		return err
	}

	log.Println("Appending patch layer from directory:", patchDir)

	layer, err := createlayer(patchDir)
	if err != nil {
		return err
	}

	newImage, err := mutate.AppendLayers(origImage, layer)
	if err != nil {
		return err
	}

	log.Println("Writing image with tag:", dest)

	_, err = daemon.Write(destTag, newImage)
	if err != nil {
		return err
	}

	log.Println("Successful")

	return nil
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
