// worker.go -- Go twin of worker.c, built BOTH static (CGO_ENABLED=0) and
// dynamic (CGO_ENABLED=1, links libc). A second toolchain in the static/dynamic
// linkage mix (see Makefile) so the loader-signature shortcut (P7) cannot be
// solved by "Go-runtime prologue == one class". Same benign behaviour: file I/O,
// a KNOWN-endpoint TCP health probe, spawn a short-lived child, exit.
//
//   go-worker-static   : CGO_ENABLED=0 go build  (pure-Go, statically linked)
//   go-worker-dynamic  : CGO_ENABLED=1 go build  (dynamically linked to libc)
//
// Usage: go-worker <health_host> <health_port>
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

func fileIO() {
	f, err := os.CreateTemp("", "benign_go_*")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	for i := 0; i < 8; i++ {
		fmt.Fprintf(f, "benign line %d\n", i)
	}
	f.Sync()
	f.Seek(0, 0)
	buf := make([]byte, 128)
	for {
		if _, e := f.Read(buf); e != nil {
			break
		}
	}
	f.Close()
}

func healthConnect(host, port string) {
	// liveness probe of a KNOWN service endpoint (not a scan); ignore result
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		tmp := make([]byte, 64)
		c.Read(tmp)
		c.Close()
	}
}

func spawnChild() {
	// short-lived helper, mirroring the C worker
	cmd := exec.Command("/bin/busybox", "true")
	if cmd.Run() != nil {
		exec.Command("/bin/true").Run()
	}
}

func main() {
	host := "127.0.0.1"
	port := "8080"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		port = os.Args[2]
	}
	fileIO()
	healthConnect(host, port)
	spawnChild()
}
