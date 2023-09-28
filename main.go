// A command to run NBD servers
package main

import (
	"flag"

	"github.com/rclone/gonbdserver/server"

	_ "github.com/rclone/gonbdserver/backend/file"
)

// main() is the main program entry
//
// this is a wrapper to enable us to put the interesting stuff in a package
func main() {
	flag.Parse()
	server.Run(nil)
}
