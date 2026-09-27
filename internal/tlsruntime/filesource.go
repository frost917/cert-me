package tlsruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"cert-me/internal/app/port"
	"cert-me/internal/secret"
)

const (
	maxTLSFileBytes       = 4 << 20
	maxPassphraseFileByte = 16 << 10
)

type TLSFilePaths struct {
	Certificate string
	Chain       string
	Key         string
	Passphrase  string
}

type FileSource struct {
	paths TLSFilePaths
}

var _ port.TLSFileSource = (*FileSource)(nil)

func NewFileSource(paths TLSFilePaths) (*FileSource, error) {
	for _, path := range []string{paths.Certificate, paths.Chain, paths.Key} {
		if strings.TrimSpace(path) == "" {
			return nil, errors.New("tlsruntime: certificate, chain, and key paths are required")
		}
	}
	return &FileSource{paths: paths}, nil
}

func (s *FileSource) Load(ctx context.Context) (port.TLSFileSourceInput, error) {
	if s == nil {
		return port.TLSFileSourceInput{}, errors.New("tlsruntime: file source is unavailable")
	}
	if ctx == nil {
		return port.TLSFileSourceInput{}, errors.New("tlsruntime: context is required")
	}
	if err := ctx.Err(); err != nil {
		return port.TLSFileSourceInput{}, err
	}
	input := port.TLSFileSourceInput{}
	cleanup := func() {
		zeroFileBytes(input.Certificate)
		zeroFileBytes(input.Chain)
		zeroFileBytes(input.Key)
		if input.Passphrase != nil {
			_ = input.Passphrase.Close()
		}
	}
	var err error
	input.Certificate, err = readConfiguredFile(ctx, s.paths.Certificate, maxTLSFileBytes)
	if err != nil {
		cleanup()
		return port.TLSFileSourceInput{}, fmt.Errorf("tlsruntime: configured certificate could not be read: %w", err)
	}
	input.Chain, err = readConfiguredFile(ctx, s.paths.Chain, maxTLSFileBytes)
	if err != nil {
		cleanup()
		return port.TLSFileSourceInput{}, fmt.Errorf("tlsruntime: configured chain could not be read: %w", err)
	}
	input.Key, err = readConfiguredFile(ctx, s.paths.Key, maxTLSFileBytes)
	if err != nil {
		cleanup()
		return port.TLSFileSourceInput{}, fmt.Errorf("tlsruntime: configured key could not be read: %w", err)
	}
	if s.paths.Passphrase != "" {
		var passphrase []byte
		passphrase, err = readConfiguredFile(ctx, s.paths.Passphrase, maxPassphraseFileByte)
		if err != nil {
			cleanup()
			return port.TLSFileSourceInput{}, fmt.Errorf("tlsruntime: configured key passphrase could not be read: %w", err)
		}
		input.Passphrase = secret.New(passphrase)
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return port.TLSFileSourceInput{}, err
	}
	return input, nil
}

func readConfiguredFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, errors.New("configured file is not regular or exceeds the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		zeroFileBytes(data)
		return nil, err
	}
	if int64(len(data)) > limit {
		zeroFileBytes(data)
		return nil, errors.New("configured file exceeds the size limit")
	}
	if err := ctx.Err(); err != nil {
		zeroFileBytes(data)
		return nil, err
	}
	return data, nil
}

func zeroFileBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
