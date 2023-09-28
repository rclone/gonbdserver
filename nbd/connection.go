package nbd

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/context"
)

// DefaultWorkers is default number of workers
var DefaultWorkers = 5

// Map of configuration text to TLS versions
var tlsVersionMap = map[string]uint16{
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
}

// Map of configuration text to TLS authentication strategies
var tlsClientAuthMap = map[string]tls.ClientAuthType{
	"none":          tls.NoClientCert,
	"request":       tls.RequestClientCert,
	"require":       tls.RequireAnyClientCert,
	"verify":        tls.VerifyClientCertIfGiven,
	"requireverify": tls.RequireAndVerifyClientCert,
}

// ConnectionParameters holds parameters for each inbound connection
type ConnectionParameters struct {
	ConnectionTimeout time.Duration // maximum time to complete negotiation
}

// Connection holds the details for each connection
type Connection struct {
	params             *ConnectionParameters // parameters
	conn               net.Conn              // the connection that is used as the NBD transport
	plainConn          net.Conn              // the unencrypted (original) connection
	tlsConn            net.Conn              // the TLS encrypted connection
	logger             *log.Logger           // a logger
	listener           *Listener             // the listener than invoked us
	export             *Export               // a pointer to the export
	backend            Backend               // the backend implementation
	wg                 sync.WaitGroup        // a waitgroup for the session; we mark this as done on exit
	rxCh               chan RequestReply     // a channel of requests that have been received, and need to be dispatched to a worker
	txCh               chan RequestReply     // a channel of outputs from the worker. By this time they have replies in that need to be transmitted
	name               string                // the name of the connection for logging purposes
	disconnectReceived int64                 // nonzero if disconnect has been received
	numInflight        int64                 // number of inflight requests

	memBlockCh         chan []byte // channel of memory blocks that are free
	memBlocksMaximum   int64       // maximum blocks that may be allocated
	memBlocksAllocated int64       // blocks allocated now
	memBlocksFreeLWM   int         // smallest number of blocks free over period
	memBlocksMutex     sync.Mutex  // protects memBlocksAllocated and memBlocksFreeLWM

	killCh    chan struct{} // closed by workers to indicate a hard close is required
	killed    bool          // true if killCh closed already
	killMutex sync.Mutex    // protects killed

	debug bool // set for output of Tx and Rx packets
}

// Backend is an interface implemented by the various backend drivers
type Backend interface {
	WriteAt(ctx context.Context, b []byte, offset int64, fua bool) (int, error) // write data b at offset, with force unit access optional
	ReadAt(ctx context.Context, b []byte, offset int64) (int, error)            // read to b at offset
	TrimAt(ctx context.Context, length int, offset int64) (int, error)          // trim
	Flush(ctx context.Context) error                                            // flush
	Close(ctx context.Context) error                                            // close
	Geometry(ctx context.Context) (uint64, uint64, uint64, uint64, error)       // size, minimum BS, preferred BS, maximum BS
	HasFua(ctx context.Context) bool                                            // does the driver support FUA?
	HasFlush(ctx context.Context) bool                                          // does the driver support flush?
}

// BackendGenFn makes backends from config
type BackendGenFn func(ctx context.Context, e *ExportConfig) (Backend, error)

// BackendMap is a map between backends and the generator function for them
var BackendMap = make(map[string]BackendGenFn)

// Export is details of an export
type Export struct {
	size               uint64 // size in bytes
	minimumBlockSize   uint64 // minimum block size
	preferredBlockSize uint64 // preferred block size
	maximumBlockSize   uint64 // maximum block size
	memoryBlockSize    uint64 // block size for memory chunks
	exportFlags        uint16 // export flags in NBD format
	name               string // name of the export
	description        string // description of the export
	readonly           bool   // true if read only
	workers            int    // number of workers
	tlsonly            bool   // true if only to be served over tls
}

// RequestReply is an internal structure for propagating requests through the channels
type RequestReply struct {
	nbdReq  Request  // the request in nbd format
	nbdRep  Reply    // the reply in nbd format
	length  uint64   // the checked length
	offset  uint64   // the checked offset
	reqData [][]byte // request data (e.g. for a write)
	repData [][]byte // reply data (e.g. for a read)
	flags   uint64   // our internal flag structure characterizing the request
}

// newConection returns a new Connection object
func newConnection(listener *Listener, logger *log.Logger, conn net.Conn, debug bool) (*Connection, error) {
	params := &ConnectionParameters{
		ConnectionTimeout: time.Second * 5,
	}
	c := &Connection{
		plainConn: conn,
		listener:  listener,
		logger:    logger,
		params:    params,
		debug:     debug,
	}
	return c, nil
}

// Error translates an error returned by golang into an NBD error
//
// FIXME This function could do with some serious work!
func Error(err error) uint32 {
	return EIO
}

// isClosedErr returns true if the error related to use of a closed connection.
//
// this is particularly foul but is used to suppress errors that relate to use of a closed connection. This is because
// they only arise as we ourselves close the connection to get blocking reads/writes to safely terminate, and thus do
// not want to report them to the user as an error
func isClosedErr(err error) bool {
	return strings.HasSuffix(err.Error(), "use of closed network connection") // YUCK!
}

// Kill kills a connection. This safely ensures the kill channel is closed if it isn't already, which will
// kill all the goroutines
func (c *Connection) Kill(ctx context.Context) {
	c.killMutex.Lock()
	defer c.killMutex.Unlock()
	if !c.killed {
		close(c.killCh)
		c.killed = true
	}
}

// GetMemory for a particular length
func (c *Connection) GetMemory(ctx context.Context, length uint64) [][]byte {
	n := (length + c.export.memoryBlockSize - 1) / c.export.memoryBlockSize
	mem := make([][]byte, n)
	c.memBlocksMutex.Lock()
	for i := uint64(0); i < n; i++ {
		var m []byte
		var ok bool
		select {
		case <-ctx.Done():
			c.memBlocksMutex.Unlock()
			return nil
		case m, ok = <-c.memBlockCh:
			if !ok {
				c.logger.Printf("[ERROR] Memory channel failed")
				c.memBlocksMutex.Unlock()
				return nil
			}
		default:
			c.memBlocksFreeLWM = 0 // ensure no more are freed
			if c.memBlocksAllocated < c.memBlocksMaximum {
				c.memBlocksAllocated++
				m = make([]byte, c.export.memoryBlockSize)
			} else {
				c.memBlocksMutex.Unlock()
				select {
				case m, ok = <-c.memBlockCh:
					if !ok {
						c.logger.Printf("[ERROR] Memory channel failed")
						return nil
					}
				case <-ctx.Done():
					return nil
				}
				c.memBlocksMutex.Lock()
			}
		}
		mem[i] = m
	}
	if freeBlocks := len(c.memBlockCh); freeBlocks < c.memBlocksFreeLWM {
		c.memBlocksFreeLWM = freeBlocks
	}
	c.memBlocksMutex.Unlock()
	return mem
}

// FreeMemory for a particular length
func (c *Connection) FreeMemory(ctx context.Context, mem [][]byte) {
	n := len(mem)
	i := 0
pushloop:
	for ; i < n; i++ {
		select {
		case <-ctx.Done():
			break pushloop
		case c.memBlockCh <- mem[i]:
			mem[i] = nil
		default:
			break pushloop
		}
	}
	c.memBlocksMutex.Lock()
	defer c.memBlocksMutex.Unlock()
	for ; i < n; i++ {
		mem[i] = nil
		c.memBlocksAllocated--
	}
}

// ZeroMemory for Connection
func (c *Connection) ZeroMemory(ctx context.Context, mem [][]byte) {
	for i := range mem {
		for j := range mem[i] {
			mem[i][j] = 0
		}
	}
}

// ReturnMemory periodically returns all memory under the low water mark back to the OS
func (c *Connection) ReturnMemory(ctx context.Context) {
	defer func() {
		c.memBlocksMutex.Lock()
		c.logger.Printf("[INFO] ReturnMemory exiting for %s alloc=%d free=%d LWM=%d", c.name, c.memBlocksAllocated, len(c.memBlockCh), c.memBlocksFreeLWM)
		c.memBlocksMutex.Unlock()
		c.Kill(ctx)
		c.wg.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			c.memBlocksMutex.Lock()
			freeBlocks := len(c.memBlockCh)
			if freeBlocks < c.memBlocksFreeLWM {
				c.memBlocksFreeLWM = freeBlocks
			}
			//c.logger.Printf("[DEBUG] Return memory for %s alloc=%d free=%d LWM=%d", c.name, c.memBlocksAllocated, freeBlocks, c.memBlocksFreeLWM)
		returnloop:
			for n := 0; n < c.memBlocksFreeLWM; n++ {
				select {
				case _, ok := <-c.memBlockCh:
					if !ok {
						return
					}
					c.memBlocksAllocated--
				default:
					break returnloop
				}
			}
			c.memBlocksFreeLWM = freeBlocks
			c.memBlocksMutex.Unlock()
		}
	}
}

func (c *Connection) binaryRead(r io.Reader, order binary.ByteOrder, data any) error {
	err := binary.Read(r, order, data)
	if err != nil {
		c.logger.Printf("[DEBUG] binary read failed: %v", err)
		return err
	}
	if c.debug {
		switch p := data.(type) {
		case *uint64:
			c.logger.Printf("[DEBUG] Rx: 0x%016x", *p)
		case *uint32:
			c.logger.Printf("[DEBUG] Rx: 0x%08x", *p)
		case *uint16:
			c.logger.Printf("[DEBUG] Rx: 0x%04x", *p)
		case *uint8:
			c.logger.Printf("[DEBUG] Rx: 0x%02x", *p)
		default:
			c.logger.Printf("[DEBUG] Rx: %#v", data)
		}
	}
	return nil
}

func (c *Connection) binaryWrite(w io.Writer, order binary.ByteOrder, data any) error {
	if c.debug {
		switch p := data.(type) {
		case uint64:
			c.logger.Printf("[DEBUG] Tx: 0x%016x", p)
		case uint32:
			c.logger.Printf("[DEBUG] Tx: 0x%08x", p)
		case uint16:
			c.logger.Printf("[DEBUG] Tx: 0x%04x", p)
		case uint8:
			c.logger.Printf("[DEBUG] Tx: 0x%02x", p)
		default:
			c.logger.Printf("[DEBUG] Tx: %#v", data)
		}
	}
	err := binary.Write(w, order, data)
	if err != nil {
		c.logger.Printf("[DEBUG] binary write failed: %v", err)
		return err
	}
	return nil
}

// Receive is the goroutine that handles decoding connection data from the socket
func (c *Connection) Receive(ctx context.Context) {
	defer func() {
		c.logger.Printf("[INFO] Receiver exiting for %s", c.name)
		c.Kill(ctx)
		c.wg.Done()
	}()
	for {
		req := RequestReply{}
		if err := c.binaryRead(c.conn, binary.BigEndian, &req.nbdReq); err != nil {
			if nerr, ok := err.(net.Error); ok {
				if nerr.Timeout() {
					c.logger.Printf("[INFO] Client %s timeout, closing connection", c.name)
					return
				}
			}
			if isClosedErr(err) {
				// Don't report this - we closed it
				return
			}
			if err == io.EOF {
				c.logger.Printf("[WARN] Client %s closed connection abruptly", c.name)
			} else {
				c.logger.Printf("[ERROR] Client %s could not read request: %s", c.name, err)
			}
			return
		}

		if req.nbdReq.Magic != RequestMagic {
			c.logger.Printf("[ERROR] Client %s had bad magic number in request", c.name)
			return
		}

		req.nbdRep = Reply{
			Magic:  ReplyMagic,
			Handle: req.nbdReq.Handle,
			Error:  0,
		}

		cmd := req.nbdReq.CommandType
		var ok bool
		if req.flags, ok = CmdTypeMap[int(cmd)]; !ok {
			c.logger.Printf("[ERROR] Client %s unknown command %d", c.name, cmd)
			return
		}

		if req.flags&CmdTSetDisconnectReceived != 0 {
			// we process this here as commands may otherwise be processed out
			// of order and per the spec we should not receive any more
			// commands after receiving a disconnect
			atomic.StoreInt64(&c.disconnectReceived, 1)
		}

		if req.flags&CmdTCheckLengthOffset != 0 {
			req.length = uint64(req.nbdReq.Length)
			req.offset = req.nbdReq.Offset
			if req.length <= 0 || req.length+req.offset > c.export.size {
				c.logger.Printf("[ERROR] Client %s gave bad offset or length", c.name)
				return
			}
			if req.length&(c.export.minimumBlockSize-1) != 0 || req.offset&(c.export.minimumBlockSize-1) != 0 || req.length > c.export.maximumBlockSize {
				c.logger.Printf("[ERROR] Client %s gave offset or length outside blocksize parameters cmd=%d (len=%08x,off=%08x,minbs=%08x,maxbs=%08x)", c.name, req.nbdReq.CommandType, req.length, req.offset, c.export.minimumBlockSize, c.export.maximumBlockSize)
				return
			}
		}

		if req.flags&CmdTReqPayload != 0 {
			if req.reqData = c.GetMemory(ctx, req.length); req.reqData == nil {
				// error already logged
				return
			}
			if req.length <= 0 {
				c.logger.Printf("[ERROR] Client %s gave bad length", c.name)
				return
			}
			length := req.length
			for i := 0; length > 0; i++ {
				blocklen := c.export.memoryBlockSize
				if blocklen > length {
					blocklen = length
				}
				n, err := io.ReadFull(c.conn, req.reqData[i][:blocklen])
				if err != nil {
					if isClosedErr(err) {
						// Don't report this - we closed it
						return
					}

					c.logger.Printf("[ERROR] Client %s can not read data to write: %s", c.name, err)
					return
				}

				if uint64(n) != blocklen {
					c.logger.Printf("[ERROR] Client %s can not read all data to write: %d != %d", c.name, n, blocklen)
					return

				}
				length -= blocklen
			}

		} else if req.flags&CmdTReqFakePayload != 0 {
			if req.reqData = c.GetMemory(ctx, req.length); req.reqData == nil {
				// error printed already
				return
			}
			c.ZeroMemory(ctx, req.reqData)
		}

		if req.flags&CmdTRepPayload != 0 {
			if req.repData = c.GetMemory(ctx, req.length); req.repData == nil {
				// error printed already
				return
			}
		}

		atomic.AddInt64(&c.numInflight, 1) // one more in flight
		if req.flags&CmdTCheckNotReadOnly != 0 && c.export.readonly {
			req.nbdRep.Error = EPERM
			select {
			case c.txCh <- req:
			case <-ctx.Done():
				return
			}
		} else {
			select {
			case c.rxCh <- req:
			case <-ctx.Done():
				return
			}
		}
		// if we've received a disconnect, just sit waiting for the
		// context to indicate we've done
		if atomic.LoadInt64(&c.disconnectReceived) > 0 {
			<-ctx.Done()
			return
		}
	}
}

// Dispatch is the goroutine used to process received items, passing the reply to the transmit goroutine
//
// one of these is run for each worker
func (c *Connection) Dispatch(ctx context.Context, n int) {
	defer func() {
		c.logger.Printf("[INFO] Dispatcher %d exiting for %s", n, c.name)
		c.Kill(ctx)
		c.wg.Done()
	}()
	//t := time.Now()
	for {
		//c.logger.Printf("[DEBUG] Client %s dispatcher %d waiting latency %s", c.name, n, checkpoint(&t))
		select {
		case <-ctx.Done():
			return
		case req, ok := <-c.rxCh:
			if !ok {
				return
			}
			//c.logger.Printf("[DEBUG] Client %s dispatcher %d command %d latency %s", c.name, n, req.nbdReq.NbdCommandType, checkpoint(&t))
			fua := req.nbdReq.CommandFlags&CmdFlagFua != 0

			addr := req.offset
			length := req.length
			switch req.nbdReq.CommandType {
			case CmdRead:
				for i := 0; length > 0; i++ {
					blocklen := c.export.memoryBlockSize
					if blocklen > length {
						blocklen = length
					}
					n, err := c.backend.ReadAt(ctx, req.repData[i][:blocklen], int64(addr))
					if err != nil {
						c.ZeroMemory(ctx, req.repData[i:])
						c.logger.Printf("[WARN] Client %s got read I/O error: %s", c.name, err)
						req.nbdRep.Error = Error(err)
						break
					} else if uint64(n) != blocklen {
						c.ZeroMemory(ctx, req.repData[i:])
						c.logger.Printf("[WARN] Client %s got incomplete read (%d != %d) at offset %d", c.name, n, length, addr)
						req.nbdRep.Error = EIO
						break
					}
					addr += blocklen
					length -= blocklen
				}
			case CmdWrite, FlagSendWriteZeroes:
				for i := 0; length > 0; i++ {
					blocklen := c.export.memoryBlockSize
					if blocklen > length {
						blocklen = length
					}
					n, err := c.backend.WriteAt(ctx, req.reqData[i][:blocklen], int64(addr), fua)
					if err != nil {
						c.logger.Printf("[WARN] Client %s got write I/O error: %s", c.name, err)
						req.nbdRep.Error = Error(err)
						break
					} else if uint64(n) != blocklen {
						c.logger.Printf("[WARN] Client %s got incomplete write (%d != %d) at offset %d", c.name, n, length, addr)
						req.nbdRep.Error = EIO
						break
					}
					addr += blocklen
					length -= blocklen
				}
			case CmdFlush:
				if err := c.backend.Flush(ctx); err != nil {
					c.logger.Printf("[WARN] Client %s got flush I/O error: %s", c.name, err)
					req.nbdRep.Error = Error(err)
					break
				}
			case CmdTrim:
				for i := 0; length > 0; i++ {
					blocklen := c.export.memoryBlockSize
					if blocklen > length {
						blocklen = length
					}
					n, err := c.backend.TrimAt(ctx, int(req.length), int64(addr))
					if err != nil {
						c.ZeroMemory(ctx, req.repData[i:])
						c.logger.Printf("[WARN] Client %s got trim I/O error: %s", c.name, err)
						req.nbdRep.Error = Error(err)
						break
					} else if uint64(n) != blocklen {
						c.ZeroMemory(ctx, req.repData[i:])
						c.logger.Printf("[WARN] Client %s got incomplete trim (%d != %d) at offset %d", c.name, n, length, addr)
						req.nbdRep.Error = EIO
						break
					}
					addr += blocklen
					length -= blocklen
				}
			case CmdDisc:
				c.waitForInflight(ctx, 1) // this request is itself in flight, so 1 is permissible
				_ = c.backend.Flush(ctx)
				c.logger.Printf("[INFO] Client %s requested disconnect", c.name)
				return
			case CmdClose:
				c.waitForInflight(ctx, 1) // this request is itself in flight, so 1 is permissible
				_ = c.backend.Flush(ctx)
				c.logger.Printf("[INFO] Client %s requested close", c.name)
				select {
				case c.txCh <- req:
				case <-ctx.Done():
				}
				c.waitForInflight(ctx, 0) // wait for this request to be no longer inflight (i.e. reply transmitted)
				c.logger.Printf("[INFO] Client %s close completed", c.name)
				return
			default:
				c.logger.Printf("[ERROR] Client %s sent unknown command %d", c.name, req.nbdReq.CommandType)
				return
			}
			select {
			case c.txCh <- req:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *Connection) waitForInflight(ctx context.Context, limit int64) {
	c.logger.Printf("[INFO] Client %s waiting for inflight requests prior to disconnect", c.name)
	for {
		if atomic.LoadInt64(&c.numInflight) <= limit {
			return
		}
		// this is pretty nasty in that it would be nicer to wait on
		// a channel or use a (non-existent) waitgroup with timer.
		// however it's only one atomic read every 10ms and this
		// will hardly ever occur
		time.Sleep(10 * time.Millisecond)
	}
}

// Transmit is the goroutine run to transmit the processed requests (now replies)
func (c *Connection) Transmit(ctx context.Context) {
	defer func() {
		c.logger.Printf("[INFO] Transmitter exiting for %s", c.name)
		c.Kill(ctx)
		c.wg.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-c.txCh:
			if !ok {
				return
			}
			if err := c.binaryWrite(c.conn, binary.BigEndian, req.nbdRep); err != nil {
				c.logger.Printf("[ERROR] Client %s can not write reply", c.name)
				return
			}
			if req.flags&CmdTRepPayload != 0 && req.repData != nil {
				length := req.length
				for i := 0; length > 0; i++ {
					blocklen := c.export.memoryBlockSize
					if blocklen > length {
						blocklen = length
					}
					if n, err := c.conn.Write(req.repData[i][:blocklen]); err != nil || uint64(n) != blocklen {
						c.logger.Printf("[ERROR] Client %s can not write reply", c.name)
						return
					}
					length -= blocklen
				}
			}
			if req.repData != nil {
				c.FreeMemory(ctx, req.repData)
			}
			if req.reqData != nil {
				c.FreeMemory(ctx, req.reqData)
			}
			// TODO: with structured replies, only do this if the 'DONE' bit is set.
			atomic.AddInt64(&c.numInflight, -1) // one less in flight
		}
	}
}

// Serve negotiates, then starts all the goroutines for processing a connection, then waits for them to be ended
func (c *Connection) Serve(parentCtx context.Context) {
	ctx, cancelFunc := context.WithCancel(parentCtx)

	c.rxCh = make(chan RequestReply, 1024)
	c.txCh = make(chan RequestReply, 1024)
	c.killCh = make(chan struct{})

	c.conn = c.plainConn
	c.name = c.plainConn.RemoteAddr().String()
	if c.name == "" {
		c.name = "[unknown]"
	}

	defer func() {
		if c.backend != nil {
			_ = c.backend.Close(ctx)
		}
		if c.tlsConn != nil {
			_ = c.tlsConn.Close()
		}
		_ = c.plainConn.Close()
		cancelFunc()
		c.Kill(ctx) // to ensure the kill channel is closed
		c.wg.Wait()
		close(c.rxCh)
		close(c.txCh)
		if c.memBlockCh != nil {
		freemem:
			for {
				select {
				case _, ok := <-c.memBlockCh:
					if !ok {
						break freemem
					}
				default:
					break freemem
				}
			}
			close(c.memBlockCh)
		}
		c.logger.Printf("[INFO] Closed connection from %s", c.name)
	}()

	if err := c.Negotiate(ctx); err != nil {
		c.logger.Printf("[INFO] Negotiation failed with %s: %v", c.name, err)
		return
	}

	c.memBlocksMaximum = int64(((c.export.maximumBlockSize + c.export.memoryBlockSize - 1) / c.export.memoryBlockSize) * 2)
	c.memBlockCh = make(chan []byte, c.memBlocksMaximum+1)

	c.name = c.name + "/" + c.export.name

	workers := c.export.workers

	if workers < 1 {
		workers = DefaultWorkers
	}

	c.logger.Printf("[INFO] Negotiation succeeded with %s, serving with %d worker(s)", c.name, workers)

	c.wg.Add(3)
	go c.Receive(ctx)
	go c.Transmit(ctx)
	go c.ReturnMemory(ctx)
	for i := 0; i < workers; i++ {
		c.wg.Add(1)
		go c.Dispatch(ctx, i)
	}

	// Wait until either we are explicitly killed or one of our
	// workers dies
	select {
	case <-c.killCh:
		c.logger.Printf("[INFO] Worker forced close for %s", c.name)
	case <-ctx.Done():
		c.logger.Printf("[INFO] Parent forced close for %s", c.name)
	}
}

// skip bytes
func skip(r io.Reader, n uint32) error {
	for n > 0 {
		l := n
		if l > 1024 {
			l = 1024
		}
		b := make([]byte, l)
		if nr, err := io.ReadFull(r, b); err != nil {
			return err
		} else if nr != int(l) {
			return errors.New("skip returned short read")
		}
		n -= l
	}
	return nil
}

// Negotiate negotiates a connection
func (c *Connection) Negotiate(ctx context.Context) error {
	err := c.conn.SetDeadline(time.Now().Add(c.params.ConnectionTimeout))
	if err != nil {
		return err
	}

	// We send a newstyle header
	nsh := NewStyleHeader{
		Magic:       NbdMagic,
		OptsMagic:   OptsMagic,
		GlobalFlags: FlagFixedNewstyle,
	}

	if !c.listener.disableNoZeroes {
		nsh.GlobalFlags |= FlagNoZeroes
	}

	if err := c.binaryWrite(c.conn, binary.BigEndian, nsh); err != nil {
		return fmt.Errorf("can not write magic header: %w", err)
	}

	// next they send client flags
	var clf ClientFlags

	if err := c.binaryRead(c.conn, binary.BigEndian, &clf); err != nil {
		return fmt.Errorf("can not read client flags: %w", err)
	}

	done := false
	// now we get options
	for !done {
		var opt ClientOpt
		if err := c.binaryRead(c.conn, binary.BigEndian, &opt); err != nil {
			return fmt.Errorf("can not read option (perhaps client dropped the connection): %w", err)
		}
		if opt.Magic != OptsMagic {
			return errors.New("bad option magic")
		}
		if opt.Len > 65536 {
			return errors.New("option is too long")
		}
		switch opt.ID {
		case OptExportName, OptInfo, OptGo:
			var name []byte

			clientSupportsBlockSizeConstraints := false

			if opt.ID == OptExportName {
				name = make([]byte, opt.Len)
				n, err := io.ReadFull(c.conn, name)
				if err != nil {
					return err
				}
				if uint32(n) != opt.Len {
					return errors.New("incomplete name")
				}
			} else {
				var nameLength uint32
				if err := c.binaryRead(c.conn, binary.BigEndian, &nameLength); err != nil {
					return fmt.Errorf("bad export name length: %w", err)
				}
				if nameLength > 4096 {
					return errors.New("name is too long")
				}
				name = make([]byte, nameLength)
				n, err := io.ReadFull(c.conn, name)
				if err != nil {
					return err
				}
				if uint32(n) != nameLength {
					return errors.New("incomplete name")
				}
				var numInfoElements uint16
				if err := c.binaryRead(c.conn, binary.BigEndian, &numInfoElements); err != nil {
					return fmt.Errorf("bad number of info elements: %w", err)
				}
				for i := uint16(0); i < numInfoElements; i++ {
					var infoElement uint16
					if err := c.binaryRead(c.conn, binary.BigEndian, &infoElement); err != nil {
						return fmt.Errorf("bad number of info elements: %w", err)
					}
					switch infoElement {
					case NbdInfoBlockSize:
						clientSupportsBlockSizeConstraints = true
					}
				}
				l := 2 + 2*uint32(numInfoElements) + 4 + nameLength
				if opt.Len > l {
					if err := skip(c.conn, opt.Len-l); err != nil {
						return err
					}
				} else if opt.Len < l {
					return errors.New("option length too short")
				}
			}

			if len(name) == 0 {
				name = []byte(c.listener.defaultExport)
			}

			// Next find our export
			ec, err := c.getExportConfig(ctx, string(name))
			if err != nil || (ec.TLSOnly && c.tlsConn == nil) {
				if opt.ID == OptExportName {
					// we have to just abort here
					if err != nil {
						return err
					}
					return errors.New("attempt to connect to TLS-only connection without TLS")
				}
				or := OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepErrUnknown,
					Length: 0,
				}
				if err == nil {
					or.Type = RepErrTLSReqd
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not send info error: %w", err)
				}
				break
			}

			// Now we know we are going to go with the export for sure
			// any failure beyond here and we are going to drop the
			// connection (assuming we aren't doing NBD_OPT_INFO)
			export, err := c.connectExport(ctx, ec)
			if err != nil {
				if opt.ID == OptExportName {
					return err
				}
				c.logger.Printf("[INFO] Could not connect client %s to %s: %v", c.name, string(name), err)
				or := OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepErrUnknown,
					Length: 0,
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not send info error: %w", err)
				}
				break
			}

			// for the reply
			name = []byte(export.name)
			description := []byte(export.description)

			if opt.ID == OptExportName {
				// this option has a unique reply format
				ed := ExportDetails{
					Size:  export.size,
					Flags: export.exportFlags,
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, ed); err != nil {
					return fmt.Errorf("can not write export details: %w", err)
				}
			} else {
				// Send NBD_INFO_EXPORT
				or := OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepInfo,
					Length: 12,
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not write info export pt1: %w", err)
				}
				ir := InfoExport{
					InfoType:          NbdInfoExport,
					ExportSize:        export.size,
					TransmissionFlags: export.exportFlags,
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, ir); err != nil {
					return fmt.Errorf("can not write info export pt2: %w", err)
				}

				// Send NBD_INFO_NAME
				or = OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepInfo,
					Length: uint32(2 + len(name)),
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not write info name pt1: %w", err)
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, uint16(NbdInfoName)); err != nil {
					return fmt.Errorf("can not write name id: %w", err)
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, name); err != nil {
					return fmt.Errorf("can not write name: %w", err)
				}

				// Send NBD_INFO_DESCRIPTION
				or = OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepInfo,
					Length: uint32(2 + len(description)),
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not write info description pt1: %w", err)
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, uint16(NbdInfoDescription)); err != nil {
					return fmt.Errorf("can not write description id: %w", err)
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, description); err != nil {
					return fmt.Errorf("can not write description: %w", err)
				}

				// Send NBD_INFO_BLOCK_SIZE
				or = OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepInfo,
					Length: 14,
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not write info block size pt1: %w", err)
				}
				ir2 := InfoBlockSize{
					InfoType:           NbdInfoBlockSize,
					MinimumBlockSize:   uint32(export.minimumBlockSize),
					PreferredBlockSize: uint32(export.preferredBlockSize),
					MaximumBlockSize:   uint32(export.maximumBlockSize),
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, ir2); err != nil {
					return fmt.Errorf("can not write info block size pt2: %w", err)
				}

				replyType := RepAck

				if export.minimumBlockSize > 1 && !clientSupportsBlockSizeConstraints {
					c.logger.Printf("[ERROR] block size negotiation failed - need ndb-client -g to force NBD_OPT_EXPORT_NAME protocol")
					replyType = RepErrBlockSizeReqd
				}

				// Send ACK or error
				or = OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   replyType,
					Length: 0,
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not info ack: %w", err)
				}
				if opt.ID == OptInfo || or.Type&RepFlagError != 0 {
					// Disassociate the backend as we are not closing
					_ = c.backend.Close(ctx)
					c.backend = nil
					break
				}
			}

			if clf.Flags&FlagCNoZeroes == 0 && opt.ID == OptExportName {
				// send 124 bytes of zeroes.
				zeroes := make([]byte, 124)
				if err := c.binaryWrite(c.conn, binary.BigEndian, zeroes); err != nil {
					return fmt.Errorf("can not write zeroes: %w", err)
				}
			}
			c.export = export
			done = true

		case OptList:
			for _, e := range c.listener.exports {
				name := []byte(e.Name)
				or := OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepServer,
					Length: uint32(len(name) + 4),
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not send list item: %w", err)
				}
				l := uint32(len(name))
				if err := c.binaryWrite(c.conn, binary.BigEndian, l); err != nil {
					return fmt.Errorf("can not send list name length: %w", err)
				}
				if n, err := c.conn.Write(name); err != nil || n != len(name) {
					return fmt.Errorf("can not send list name: %w", err)
				}
			}
			or := OptReply{
				Magic:  RepMagic,
				ID:     opt.ID,
				Type:   RepAck,
				Length: 0,
			}
			if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
				return fmt.Errorf("can not send list ack: %w", err)
			}
		case OptStarttls:
			if c.listener.tlsconfig == nil || c.tlsConn != nil {
				// say it's unsuppported
				c.logger.Printf("[INFO] Rejecting upgrade of connection with %s to TLS", c.name)
				or := OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepErrUnsup,
					Length: 0,
				}
				if c.tlsConn != nil { // TLS is already negotiated
					or.Type = RepErrInvalid
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not reply to unsupported TLS option: %w", err)
				}
			} else {
				or := OptReply{
					Magic:  RepMagic,
					ID:     opt.ID,
					Type:   RepAck,
					Length: 0,
				}
				if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
					return fmt.Errorf("can not send TLS ack: %w", err)
				}
				c.logger.Printf("[INFO] Upgrading connection with %s to TLS", c.name)
				// switch over to TLS
				tls := tls.Server(c.conn, c.listener.tlsconfig)
				c.tlsConn = tls
				c.conn = tls
				// explicitly handshake so we get an error here if there is an issue
				if err := tls.Handshake(); err != nil {
					return fmt.Errorf("TLS handshake failed: %s", err)
				}
			}
		case OptAbort:
			or := OptReply{
				Magic:  RepMagic,
				ID:     opt.ID,
				Type:   RepAck,
				Length: 0,
			}
			if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
				return fmt.Errorf("can not send abort ack: %w", err)
			}
			return errors.New("Connection aborted by client")
		default:
			// eat the option
			if err := skip(c.conn, opt.Len); err != nil {
				return err
			}
			// say it's unsuppported
			or := OptReply{
				Magic:  RepMagic,
				ID:     opt.ID,
				Type:   RepErrUnsup,
				Length: 0,
			}
			if err := c.binaryWrite(c.conn, binary.BigEndian, or); err != nil {
				return fmt.Errorf("can not reply to unsupported option: %w", err)
			}
		}
	}

	return c.conn.SetDeadline(time.Time{})
}

// getExport generates an export for a given name
func (c *Connection) getExportConfig(ctx context.Context, name string) (*ExportConfig, error) {
	for _, ec := range c.listener.exports {
		if ec.Name == name {
			return &ec, nil
		}
	}
	return nil, errors.New("no such export")
}

// round a uint64 up to the next power of two
func roundUpToNextPowerOfTwo(x uint64) uint64 {
	var r uint64 = 1
	for i := 0; i < 64; i++ {
		if x <= r {
			return r
		}
		r = r << 1
	}
	return 0 // won't fit in uint64 :-(
}

// connectExport generates an export for a given name, and connects to it using the chosen backend
func (c *Connection) connectExport(ctx context.Context, ec *ExportConfig) (*Export, error) {
	forceFlush, forceNoFlush, err := IsTrueFalse(ec.DriverParameters["flush"])
	if err != nil {
		return nil, err
	}
	forceFua, forceNoFua, err := IsTrueFalse(ec.DriverParameters["fua"])
	if err != nil {
		return nil, err
	}
	var (
		backendgen BackendGenFn
		ok         bool
		backend    Backend
	)
	if backendgen, ok = BackendMap[strings.ToLower(ec.Driver)]; !ok {
		return nil, fmt.Errorf("no such driver %s", ec.Driver)
	}
	if backend, err = backendgen(ctx, ec); err != nil {
		return nil, err
	}
	size, minimumBlockSize, preferredBlockSize, maximumBlockSize, err := backend.Geometry(ctx)
	if err != nil {
		_ = backend.Close(ctx)
		return nil, err
	}
	if c.backend != nil {
		_ = c.backend.Close(ctx)
	}
	c.backend = backend
	if ec.MinimumBlockSize != 0 {
		minimumBlockSize = ec.MinimumBlockSize
	}
	if ec.PreferredBlockSize != 0 {
		preferredBlockSize = ec.PreferredBlockSize
	}
	if ec.MaximumBlockSize != 0 {
		maximumBlockSize = ec.MaximumBlockSize
	}
	if minimumBlockSize == 0 {
		minimumBlockSize = 1
	}
	minimumBlockSize = roundUpToNextPowerOfTwo(minimumBlockSize)
	preferredBlockSize = roundUpToNextPowerOfTwo(preferredBlockSize)
	// ensure preferredBlockSize is a multiple of the minimum block size
	preferredBlockSize = preferredBlockSize & ^(minimumBlockSize - 1)
	if preferredBlockSize < minimumBlockSize {
		preferredBlockSize = minimumBlockSize
	}
	// ensure maximumBlockSize is a multiple of preferredBlockSize
	maximumBlockSize = maximumBlockSize & ^(preferredBlockSize - 1)
	if maximumBlockSize < preferredBlockSize {
		maximumBlockSize = preferredBlockSize
	}
	flags := FlagHasFlags | FlagSendWriteZeroes | FlagSendClose
	if (backend.HasFua(ctx) || forceFua) && !forceNoFua {
		flags |= FlagSendFua
	}
	if (backend.HasFlush(ctx) || forceFlush) && !forceNoFlush {
		flags |= FlagSendFlush
	}
	size = size & ^(minimumBlockSize - 1)
	return &Export{
		size:               size,
		exportFlags:        flags,
		name:               ec.Name,
		readonly:           ec.ReadOnly,
		workers:            ec.Workers,
		tlsonly:            ec.TLSOnly,
		description:        ec.Description,
		minimumBlockSize:   minimumBlockSize,
		preferredBlockSize: preferredBlockSize,
		maximumBlockSize:   maximumBlockSize,
		memoryBlockSize:    preferredBlockSize,
	}, nil
}

// RegisterBackend should be called to register a backend with the server
func RegisterBackend(name string, generator func(ctx context.Context, e *ExportConfig) (Backend, error)) {
	BackendMap[name] = generator
}

// GetBackendNames returns a list of all known Backends
func GetBackendNames() []string {
	b := make([]string, len(BackendMap))
	i := 0
	for k := range BackendMap {
		b[i] = k
		i++
	}
	sort.Strings(b)
	return b
}
