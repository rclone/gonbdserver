package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"github.com/rclone/gonbdserver/nbd"
)

const ConfigTemplate = `
servers:
- protocol: unix
  address: {{.TempDir}}/nbd.sock
  exports:
  - name: foo
    driver: {{.Driver}}
    path: {{.TempDir}}/nbd.img
    workers: 20
{{if .NoFlush}}
    flush: false
    fua: false
{{end}}
  - name: bar
    driver: rbd
    readonly: false
    image: rbdbar
{{if .TLS}}
  tls:
    keyfile: {{.TempDir}}/server-key.pem
    certfile: {{.TempDir}}/server-cert.pem
    cacertfile: {{.TempDir}}/client-cert.pem
    servername: localhost
    clientauth: requireverify
{{end}}
logging:
`

var longtests = flag.Bool("longtests", false, "enable long tests")
var noFlush = flag.Bool("noflush", false, "Disable flush and FUA (for benchmarking - do not use in production")

type TestConfig struct {
	TLS     bool
	TempDir string
	Driver  string
	NoFlush bool
}

type NbdInstance struct {
	t                 *testing.T
	quit              chan struct{}
	closed            bool
	closedMutex       sync.Mutex
	plainConn         net.Conn
	tlsConn           net.Conn
	conn              net.Conn
	transmissionFlags uint16
	TestConfig
}

var nextHandle uint64

func getHandle() uint64 {
	return atomic.AddUint64(&nextHandle, 1)
}

func StartNbd(t *testing.T, tc TestConfig) *NbdInstance {
	ni := &NbdInstance{
		t:          t,
		quit:       make(chan struct{}),
		TestConfig: tc,
	}

	if TempDir, err := os.MkdirTemp("", "nbdtest"); err != nil {
		t.Fatalf("Could not create test directory: %v", err)
	} else {
		ni.TempDir = TempDir
	}

	if err := os.WriteFile(path.Join(ni.TempDir, "server-key.pem"), []byte(testServerKey), 0644); err != nil {
		t.Fatalf("Could not write server key")
	}
	if err := os.WriteFile(path.Join(ni.TempDir, "server-cert.pem"), []byte(testServerCert), 0644); err != nil {
		t.Fatalf("Could not write server cert")
	}
	if err := os.WriteFile(path.Join(ni.TempDir, "client-key.pem"), []byte(testClientKey), 0644); err != nil {
		t.Fatalf("Could not write client key")
	}
	if err := os.WriteFile(path.Join(ni.TempDir, "client-cert.pem"), []byte(testClientCert), 0644); err != nil {
		t.Fatalf("Could not write client key")
	}

	confFile := path.Join(ni.TempDir, "gonbdserver.conf")

	tpl := template.Must(template.New("config").Parse(ConfigTemplate))

	cf, err := os.Create(confFile)
	if err != nil {
		t.Fatalf("cannot create config file: %v", err)
	}

	if err := tpl.Execute(cf, ni.TestConfig); err != nil {
		t.Fatalf("executing template: %v", err)
	}
	_ = cf.Close()

	oldArgs := os.Args
	os.Args = []string{
		"gonbdserver",
		"-f",
		"-c",
		confFile,
	}
	flag.Parse()
	control := &Control{
		quit: ni.quit,
	}
	go Run(control)
	time.Sleep(100 * time.Millisecond)
	os.Args = oldArgs
	return ni
}

func (ni *NbdInstance) CloseConnection() {
	// fmt.Fprintf(os.Stderr, ">>>> CloseConnection()\n")
	ni.closedMutex.Lock()
	defer ni.closedMutex.Unlock()
	if ni.closed {
		return
	}
	if ni.plainConn != nil {
		_ = ni.plainConn.Close()
		ni.plainConn = nil
	}
	if ni.tlsConn != nil {
		_ = ni.tlsConn.Close()
		ni.tlsConn = nil
	}
	close(ni.quit)
	ni.closed = true
}

func (ni *NbdInstance) Close() {
	ni.CloseConnection()
	time.Sleep(100 * time.Millisecond)
	_ = os.RemoveAll(ni.TempDir)
}

// make an appropriate TLS config
func (ni *NbdInstance) getTLSConfig(t *testing.T) (*tls.Config, error) {
	keyFile := path.Join(ni.TempDir, "client-key.pem")
	certFile := path.Join(ni.TempDir, "client-cert.pem")
	caFile := path.Join(ni.TempDir, "server-cert.pem")

	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Load CA cert
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "localhost",
	}
	return tlsConfig, nil
}

func (ni *NbdInstance) Connect(t *testing.T) error {
	var err error
	ni.plainConn, err = net.Dial("unix", path.Join(ni.TempDir, "nbd.sock"))
	if err != nil {
		return err
	}
	ni.conn = ni.plainConn
	_ = ni.conn.SetDeadline(time.Now().Add(time.Second))

	var magic uint64
	if err = binary.Read(ni.conn, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("Read of magic errored: %v", err)
	}
	if magic != nbd.NbdMagic {
		return fmt.Errorf("Bad magic")
	}
	var optsMagic uint64
	if err = binary.Read(ni.conn, binary.BigEndian, &optsMagic); err != nil {
		return fmt.Errorf("Read of opts magic errored: %v", err)
	}
	if optsMagic != nbd.OptsMagic {
		return fmt.Errorf("Bad magic")
	}
	var handshakeFlags uint16
	if err = binary.Read(ni.conn, binary.BigEndian, &handshakeFlags); err != nil {
		return fmt.Errorf("Read of handshake flags errored: %v", err)
	}
	if handshakeFlags != nbd.FlagFixedNewstyle|nbd.FlagNoZeroes {
		return fmt.Errorf("Unexpected handshake flags")
	}
	var clientFlags uint32 = nbd.FlagCFixedNewstyle | nbd.FlagCNoZeroes
	if err = binary.Write(ni.conn, binary.BigEndian, clientFlags); err != nil {
		return fmt.Errorf("Could not send client flags")
	}

	t.Logf("Connected")

	if ni.TLS {
		tlsOpt := nbd.ClientOpt{
			Magic: nbd.OptsMagic,
			ID:    nbd.OptStarttls,
			Len:   0,
		}
		if err = binary.Write(ni.conn, binary.BigEndian, tlsOpt); err != nil {
			return fmt.Errorf("Could not send start tls option")
		}
		var tlsOptReply nbd.OptReply
		if err := binary.Read(ni.conn, binary.BigEndian, &tlsOptReply); err != nil {
			return fmt.Errorf("Could not receive Tls option reply")
		}
		if tlsOptReply.Magic != nbd.RepMagic {
			return fmt.Errorf("Tls option reply had wrong magic (%x)", tlsOptReply.Magic)
		}
		if tlsOptReply.ID != nbd.OptStarttls {
			return fmt.Errorf("Tls option reply had wrong id")
		}
		if tlsOptReply.Type != nbd.RepAck {
			return fmt.Errorf("Tls option reply had wrong reply type")
		}
		if tlsOptReply.Length != 0 {
			return fmt.Errorf("Tls option reply had bogus length")
		}

		tlsConfig, err := ni.getTLSConfig(t)
		if err != nil {
			return fmt.Errorf("Could not get TLS config: %v", err)
		}

		tls := tls.Client(ni.conn, tlsConfig)
		ni.tlsConn = tls
		ni.conn = tls
		_ = ni.plainConn.SetDeadline(time.Time{})
		_ = ni.conn.SetDeadline(time.Now().Add(time.Second))

		// explicitly handshake so we get an error here if there is an issue
		if err := tls.Handshake(); err != nil {
			fmt.Println("oops", err)
			return fmt.Errorf("TLS handshake failed: %s", err)
		}
	}

	listOpt := nbd.ClientOpt{
		Magic: nbd.OptsMagic,
		ID:    nbd.OptList,
		Len:   0,
	}
	if err = binary.Write(ni.conn, binary.BigEndian, listOpt); err != nil {
		return fmt.Errorf("Could not send list option")
	}

	exports := 0
listloop:
	for {
		var listOptReply nbd.OptReply
		if err := binary.Read(ni.conn, binary.BigEndian, &listOptReply); err != nil {
			return fmt.Errorf("Could not receive list option reply")
		}
		if listOptReply.Magic != nbd.RepMagic {
			return fmt.Errorf("List option reply had wrong magic (%x)", listOptReply.Magic)
		}
		if listOptReply.ID != nbd.OptList {
			return fmt.Errorf("List option reply had wrong id")
		}
		switch listOptReply.Type {
		case nbd.RepAck:
			break listloop
		case nbd.RepServer:
			var namelen uint32
			if err := binary.Read(ni.conn, binary.BigEndian, &namelen); err != nil {
				return fmt.Errorf("Could not receive list option reply name length")
			}
			name := make([]byte, namelen)
			if err := binary.Read(ni.conn, binary.BigEndian, &name); err != nil {
				return fmt.Errorf("Could not receive list option reply name")
			}
			if listOptReply.Length > namelen+4 {
				junk := make([]byte, listOptReply.Length-namelen-4)
				if err := binary.Read(ni.conn, binary.BigEndian, &junk); err != nil {
					return fmt.Errorf("Could not receive list option reply name junk")
				}
			}
			t.Logf("Found export '%s'", string(name))
			exports++
		default:
			return fmt.Errorf("List option reply type was unexpected")
		}
	}
	if exports != 2 {
		return fmt.Errorf("Unexpected number of exports")
	}

	_ = ni.conn.SetDeadline(time.Time{})
	return nil
}

func (ni *NbdInstance) Abort(t *testing.T) error {
	var err error

	opt := nbd.ClientOpt{
		Magic: nbd.OptsMagic,
		ID:    nbd.OptAbort,
		Len:   0,
	}
	if err = binary.Write(ni.conn, binary.BigEndian, opt); err != nil {
		return fmt.Errorf("Could not send start abort option")
	}
	var optReply nbd.OptReply
	if err := binary.Read(ni.conn, binary.BigEndian, &optReply); err != nil {
		return fmt.Errorf("Could not receive abort option reply")
	}
	if optReply.Magic != nbd.RepMagic {
		return fmt.Errorf("abort option reply had wrong magic (%x)", optReply.Magic)
	}
	if optReply.ID != nbd.OptAbort {
		return fmt.Errorf("abort option reply had wrong id")
	}
	if optReply.Type != nbd.RepAck {
		return fmt.Errorf("abort option reply had wrong reply type")
	}
	if optReply.Length != 0 {
		return fmt.Errorf("abort option reply had bogus length")
	}
	return nil
}

func (ni *NbdInstance) Go(t *testing.T) error {
	var err error

	export := "foo"

	opt := nbd.ClientOpt{
		Magic: nbd.OptsMagic,
		ID:    nbd.OptGo,
		Len:   uint32(2 + 2*1 + 4 + len(export)),
	}
	if err = binary.Write(ni.conn, binary.BigEndian, opt); err != nil {
		return fmt.Errorf("Could not send go option")
	}
	var nameLength = uint32(len(export))
	if err = binary.Write(ni.conn, binary.BigEndian, nameLength); err != nil {
		return fmt.Errorf("Could not send go export length")
	}
	if err = binary.Write(ni.conn, binary.BigEndian, []byte(export)); err != nil {
		return fmt.Errorf("Could not send go export name")
	}
	var numInfoElements uint16 = 1
	if err = binary.Write(ni.conn, binary.BigEndian, numInfoElements); err != nil {
		return fmt.Errorf("Could not send number of elements for go option")
	}
	var infoElement uint16 = nbd.NbdInfoBlockSize
	if err = binary.Write(ni.conn, binary.BigEndian, infoElement); err != nil {
		return fmt.Errorf("Could not send go info element")
	}
infoloop:
	for {
		var optReply nbd.OptReply
		if err := binary.Read(ni.conn, binary.BigEndian, &optReply); err != nil {
			return fmt.Errorf("Could not receive go option reply")
		}
		if optReply.Magic != nbd.RepMagic {
			return fmt.Errorf("Go option reply had wrong magic (%x)", optReply.Magic)
		}
		if optReply.ID != nbd.OptGo {
			return fmt.Errorf("Go option reply had wrong id")
		}
		switch optReply.Type {
		case nbd.RepAck:
			break infoloop
		case nbd.RepInfo:
			var infotype uint16
			if err := binary.Read(ni.conn, binary.BigEndian, &infotype); err != nil {
				return fmt.Errorf("Could not receive go option reply name length")
			}
			switch infotype {
			case nbd.NbdInfoExport:
				if optReply.Length != 12 {
					return fmt.Errorf("Bad length in nbd.NBD_INFO_EXPORT")
				}
				var exportSize uint64
				var transmissionFlags uint16
				if err := binary.Read(ni.conn, binary.BigEndian, &exportSize); err != nil {
					return fmt.Errorf("Could not receive nbd.NBD_INFO_EXPORT export size")
				}
				if err := binary.Read(ni.conn, binary.BigEndian, &transmissionFlags); err != nil {
					return fmt.Errorf("Could not receive nbd.NBD_INFO_EXPORT transmission flags")
				}
				ni.transmissionFlags = transmissionFlags
				t.Logf("Transmission flags: FLUSH=%v, FUA=%v",
					transmissionFlags&nbd.FlagSendFlush != 0,
					transmissionFlags&nbd.FlagSendFua != 0)
			default:
				t.Logf("Ignoring info type %d", infotype)
				if optReply.Length > 2 {
					junk := make([]byte, optReply.Length-2)
					if err := binary.Read(ni.conn, binary.BigEndian, &junk); err != nil {
						return fmt.Errorf("Could not receive go option reply name junk")
					}
				}
			}
		default:
			return fmt.Errorf("List option reply type was unexpected")
		}
	}

	return nil
}

func (ni *NbdInstance) CreateFile(t *testing.T, size int64) error {
	filename := path.Join(ni.TempDir, "nbd.img")
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(size); err != nil {
		return err
	}
	return nil
}

func (ni *NbdInstance) Disconnect(t *testing.T) error {
	var err error

	cmd := nbd.Request{
		Magic:        nbd.RequestMagic,
		CommandFlags: 0,
		CommandType:  nbd.CmdDisc,
		Handle:       getHandle(),
		Offset:       0,
		Length:       0,
	}
	if err = binary.Write(ni.conn, binary.BigEndian, cmd); err != nil {
		return fmt.Errorf("Could not send disconnect command")
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}

func doTestConnection(t *testing.T, tls bool) {
	ni := StartNbd(t, TestConfig{TLS: tls, NoFlush: *noFlush})
	defer ni.Close()

	if err := ni.Connect(t); err != nil {
		t.Logf("Error on connect: %v", err)
		t.Fail()
		return
	}
	if err := ni.Abort(t); err != nil {
		t.Logf("Error on abort: %v", err)
		t.Fail()
		return
	}
}

func TestConnection(t *testing.T) {
	doTestConnection(t, false)
}

func TestConnectionTls(t *testing.T) {
	doTestConnection(t, true)
}

func doTestConnectionIntegrity(t *testing.T, transationLog []byte, tls bool, driver string) {
	if _, ok := nbd.BackendMap[driver]; !ok {
		t.Skipf("Skipping test as driver %s not built", driver)
		return
	}
	ni := StartNbd(t, TestConfig{TLS: tls, Driver: driver, NoFlush: *noFlush})
	defer ni.Close()

	if err := ni.CreateFile(t, 50*1024*1024); err != nil {
		t.Logf("Error on create file: %v", err)
		t.Fail()
		return
	}

	if err := ni.Connect(t); err != nil {
		t.Logf("Error on connect: %v", err)
		t.Fail()
		return
	}
	if err := ni.Go(t); err != nil {
		t.Logf("Error on go: %v", err)
		t.Fail()
		return
	}

	it := ni.NewIntegrityTest(t, transationLog)
	defer it.Close()

	if err := it.Run(); err != nil {
		t.Logf("Error on Integrity Test: %v", err)
		t.Fail()
		return
	}

}

func TestConnectionIntegrity(t *testing.T) {
	doTestConnectionIntegrity(t, []byte(testTransactionLog), false, "file")
}

func TestConnectionIntegrityTls(t *testing.T) {
	doTestConnectionIntegrity(t, []byte(testTransactionLog), true, "file")
}

func TestConnectionIntegrityHuge(t *testing.T) {
	if !*longtests {
		t.Skip("Skipping this test as long tests not enabled (use -longtests to enable)")
	} else {
		doTestConnectionIntegrity(t, []byte(testHugeTransactionLog), false, "file")
	}
}

func TestConnectionIntegrityHugeTls(t *testing.T) {
	if !*longtests {
		t.Skip("Skipping this test as long tests not enabled (use -longtests to enable)")
	} else {
		doTestConnectionIntegrity(t, []byte(testHugeTransactionLog), true, "file")
	}
}

func TestAioConnectionIntegrity(t *testing.T) {
	doTestConnectionIntegrity(t, []byte(testTransactionLog), false, "aiofile")
}

func TestAioConnectionIntegrityTls(t *testing.T) {
	doTestConnectionIntegrity(t, []byte(testTransactionLog), true, "aiofile")
}

func TestAioConnectionIntegrityHuge(t *testing.T) {
	if !*longtests {
		t.Skip("Skipping this test as long tests not enabled (use -longtests to enable)")
	} else {
		doTestConnectionIntegrity(t, []byte(testHugeTransactionLog), false, "aiofile")
	}
}

func TestAioConnectionIntegrityHugeTls(t *testing.T) {
	if !*longtests {
		t.Skip("Skipping this test as long tests not enabled (use -longtests to enable)")
	} else {
		doTestConnectionIntegrity(t, []byte(testHugeTransactionLog), true, "aiofile")
	}
}
