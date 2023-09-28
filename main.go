package main

import (
	"flag"
	"github.com/ncw/gonbdserver/nbd"
)

// main() is the main program entry
//
// this is a wrapper to enable us to put the interesting stuff in a package
func main() {
	flag.Parse()
	nbd.Run(nil)
}
