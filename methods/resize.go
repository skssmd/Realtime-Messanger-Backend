package methods

import (
	"bytes"
	"image"
	"image/jpeg"
	"image/png"
	"mime/multipart"

	"github.com/nfnt/resize"
)

// CompressImage resizes and compresses an image to reduce its size.
func CompressImage(file multipart.File, contentType string) (*bytes.Buffer, error) {
	img, _, err := image.Decode(file)
	if err != nil {
		return nil, err
	}

	// Resize the image (width: 500px, height auto-scaled)
	resizedImg := resize.Resize(360, 0, img, resize.Lanczos3)

	// Create a buffer to hold the compressed image
	var buf bytes.Buffer

	if contentType == "image/png" {
		// Encode as PNG (lossless but larger)
		err = png.Encode(&buf, resizedImg)
	} else {
		// Encode as JPEG with quality 70 (reduces file size)
		err = jpeg.Encode(&buf, resizedImg, &jpeg.Options{Quality: 70})
	}

	if err != nil {
		return nil, err
	}

	return &buf, nil
}
