package nbd

import (
	"fmt"
	"log"
	"sync"

	"golang.org/x/net/context"
)

// ServerConfig holds the config that applies to each server (i.e. listener)
type ServerConfig struct {
	Protocol        string         // protocol it should listen on (in net.Conn form)
	Address         string         // address to listen on
	DefaultExport   string         // name of default export
	Exports         []ExportConfig // array of configurations of exported items
	TLS             TLSConfig      // TLS configuration
	DisableNoZeroes bool           // Disable NoZereos extension
}

// ExportConfig holds the config for one exported item
type ExportConfig struct {
	Name               string                 // name of the export
	Description        string                 // description of export
	Driver             string                 // name of the driver
	ReadOnly           bool                   // true of the export should be opened readonly
	Workers            int                    // number of concurrent workers
	TLSOnly            bool                   // true if the export should only be served over TLS
	MinimumBlockSize   uint64                 // minimum block size
	PreferredBlockSize uint64                 // preferred block size
	MaximumBlockSize   uint64                 // maximum block size
	DriverParameters   DriverParametersConfig `yaml:",inline"` // driver parameters. These are an arbitrary map. Inline means they go aside the foregoing
}

// TLSConfig has the configuration for TLS
type TLSConfig struct {
	KeyFile    string // path to TLS key file
	CertFile   string // path to TLS cert file
	ServerName string // server name
	CaCertFile string // path to certificate file
	ClientAuth string // client authentication strategy
	MinVersion string // minimum TLS version
	MaxVersion string // maximum TLS version
}

// DriverParametersConfig is an arbitrary map of other parameters in string format
type DriverParametersConfig map[string]string

// IsTrue determines whether an argument is true
func IsTrue(v string) (bool, error) {
	if v == "true" {
		return true, nil
	} else if v == "false" || v == "" {
		return false, nil
	}
	return false, fmt.Errorf("unknown boolean value: %s", v)
}

// IsFalse determines whether an argument is false
func IsFalse(v string) (bool, error) {
	if v == "false" {
		return true, nil
	} else if v == "true" || v == "" {
		return false, nil
	}
	return false, fmt.Errorf("unknown boolean value: %s", v)
}

// IsTrueFalse determines whether an argument is true or fals
func IsTrueFalse(v string) (bool, bool, error) {
	if v == "true" {
		return true, false, nil
	} else if v == "false" {
		return false, true, nil
	} else if v == "" {
		return false, false, nil
	}
	return false, false, fmt.Errorf("unknown boolean value: %s", v)
}

// StartServer starts a single server.
//
// A parent context is given in which the listener runs, as well as a session context in which the sessions (connections) themselves run.
// This enables the sessions to be retained when the listener is cancelled on a SIGHUP
func StartServer(parentCtx context.Context, sessionParentCtx context.Context, sessionWaitGroup *sync.WaitGroup, logger *log.Logger, s ServerConfig) {
	ctx, cancelFunc := context.WithCancel(parentCtx)

	defer func() {
		cancelFunc()
		logger.Printf("[INFO] Stopping server %s:%s", s.Protocol, s.Address)
	}()

	logger.Printf("[INFO] Starting server %s:%s", s.Protocol, s.Address)

	if l, err := NewListener(logger, s); err != nil {
		logger.Printf("[ERROR] Could not create listener for %s:%s: %v", s.Protocol, s.Address, err)
	} else {
		l.Listen(ctx, sessionParentCtx, sessionWaitGroup)
	}
}
