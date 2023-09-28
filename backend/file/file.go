// Package file implements an nbd.Backend for serving from a file.
package file

import (
	"os"

	"github.com/rclone/gonbdserver/nbd"
	"golang.org/x/net/context"
)

// Backend implements nbd.Backend
type Backend struct {
	file *os.File
	size uint64
}

// WriteAt implements Backend.WriteAt
func (fb *Backend) WriteAt(ctx context.Context, b []byte, offset int64, fua bool) (int, error) {
	n, err := fb.file.WriteAt(b, offset)
	if err != nil || !fua {
		return n, err
	}
	err = fb.file.Sync()
	if err != nil {
		return 0, err
	}
	return n, err
}

// ReadAt implements Backend.ReadAt
func (fb *Backend) ReadAt(ctx context.Context, b []byte, offset int64) (int, error) {
	return fb.file.ReadAt(b, offset)
}

// TrimAt implements Backend.TrimAt
func (fb *Backend) TrimAt(ctx context.Context, length int, offset int64) (int, error) {
	return length, nil
}

// Flush implements Backend.Flush
func (fb *Backend) Flush(ctx context.Context) error {
	return nil
}

// Close implements Backend.Close
func (fb *Backend) Close(ctx context.Context) error {
	return fb.file.Close()
}

// Geometry implements Backend.Geometry
func (fb *Backend) Geometry(ctx context.Context) (uint64, uint64, uint64, uint64, error) {
	return fb.size, 1, 32 * 1024, 128 * 1024 * 1024, nil
}

// HasFua implements Backend.HasFua
func (fb *Backend) HasFua(ctx context.Context) bool {
	return true
}

// HasFlush implements Backend.HasFua
func (fb *Backend) HasFlush(ctx context.Context) bool {
	return true
}

// New generates a new file backend
func New(ctx context.Context, ec *nbd.ExportConfig) (nbd.Backend, error) {
	perms := os.O_RDWR
	if ec.ReadOnly {
		perms = os.O_RDONLY
	}
	if s, err := nbd.IsTrue(ec.DriverParameters["sync"]); err != nil {
		return nil, err
	} else if s {
		perms |= os.O_SYNC
	}
	file, err := os.OpenFile(ec.DriverParameters["path"], perms, 0666)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Backend{
		file: file,
		size: uint64(stat.Size()),
	}, nil
}

// Register our backend
func init() {
	nbd.RegisterBackend("file", New)
}
