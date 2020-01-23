package clamd

import (
	"net"
	"net/url"
	"time"
	"fmt"
	"strings"
)

/* Variables */

//ClamD : connection object in charge of
// handling most ClamD functions
type ClamD struct {
	addr string
	url  *url.URL
}

//ClamDStats : statistics object returned from clamav-daemon
// on stat command
type ClamDStats struct {
	Pools    string
	State    string
	Threads  string
	Memstats string
	Queue string
}

var (
	EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

	errNoResp = fmt.Errorf("error no response")
)

/* Functions */

//NewClamd : spawn new ClamD instance to sent commands to ClamAV-Daemon
func NewClamd(addr string) (*ClamD, error) {
	// attempt to parse addr as connection url
	url, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	// spawn ClamD
	return &ClamD{
		addr: addr,
		url: url,
	}, nil
}

//NewClamdTCP : spawn new clamd instance with default tcp address
func NewClamdTCP() (*ClamD, error) {
	return NewClamd("tcp://127.0.0.1:3310")
}

//NewClamdUnix : spawn new clamd instance with default unix address
func NewClamdUnix() (*ClamD, error) {
	return NewClamd("unix:///var/run/clamav/clamd.ctl")
}

/* Methods */

//(*ClamD).spawnConn : attempt to spawn connection to clamd
func (d *ClamD) spawnConn() (*clamdConn, error) {
	var (
		err   error
		conn  *clamdConn
		connR net.Conn
	)
	switch d.url.Scheme {
	case "tcp":  connR, err = net.DialTimeout("tcp", d.url.Host, 2 * time.Second)
	case "unix": connR, err = net.Dial("unix", d.url.Path)
	default:     connR, err = net.Dial("unix", d.addr)
	}
	if err != nil {
		return nil, err
	}
	conn = &clamdConn{connR}
	return conn, err
}

//(*ClamD).command : run a basic command and return result from clamd
func (d *ClamD) command(cmd string) ([]*Result, error) {
	// spawn connection
	conn, err := d.spawnConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// run command
	if err = conn.Command(cmd); err != nil {
		return nil, err
	}
	return conn.Responses(), err
}

//(*ClamD).commandAwait : run command and await specific expected response
func (d *ClamD) commandAwait(cmd, await string) error {
	// attempt to run basic command
	res, err := d.command(cmd)
	if err != nil {
		return err
	}
	// check output for expected response
	for _, r := range res {
		if r.raw == await {
			return nil
		}
		return fmt.Errorf("invalid response: %s", r.raw)
	}
	return errNoResp
}

//(*ClamD).Ping : attempt basic ping command to ClamD
func (d *ClamD) Ping() error {
	return d.commandAwait("PING", "PONG")
}

//(*ClamD).Reload : attempt to reload ClamD
func (d *ClamD) Reload() error {
	return d.commandAwait("RELOAD", "RELOADING")
}

//(*ClamD).Shutdown : send shutdown command to ClamD
func (d *ClamD) Shutdown() error {
	_, err := d.command("SHUTDOWN")
	return err
}

//(*ClamD).Version : return version information from clamd
func (d *ClamD) Version() (string, error) {
	out, err := d.command("VERSION")
	if err != nil {
		return "", err
	}
	if len(out) == 0 {
		return "", errNoResp
	}
	return out[0].raw, nil
}

//(*ClamD).Stats : return statistics for ClamD
func (d *ClamD) Stats() (*ClamDStats, error) {
	results, err := d.command("STATS")
	if err != nil {
		return nil, err
	}
	stats := &ClamDStats{}
	for _, r := range results {
		switch {
		case strings.HasPrefix(r.raw, "POOLS"):
			stats.Pools = r.raw[7:]
		case strings.HasPrefix(r.raw, "STATE"):
			stats.State = r.raw[7:]
		case strings.HasPrefix(r.raw, "THREADS"):
			stats.Threads = r.raw[9:]
		case strings.HasPrefix(r.raw, "QUEUE"):
			stats.Queue = r.raw[7:]
		case strings.HasPrefix(r.raw, "MEMSTATS"):
			stats.Memstats = r.raw[10:]
		case strings.HasPrefix(r.raw, "END"):
		default:
		}
	}
	return stats, nil
}

//(*ClamD).NewInStream : return stream object in charge
// of passing and collecting results from incoming bytes
func (d *ClamD) NewInStream() (*InStream, error) {
	// attempt to spawn connection
	conn, err := d.spawnConn()
	if err != nil {
		return nil, err
	}
	// attempt to start in-stream command
	if err = conn.Command("INSTREAM"); err != nil {
		conn.Close()
		return nil, err
	}
	// return stream object
	return &InStream{
		chSize: 1024,
		conn: conn,
	}, nil
}

//(*ClamD).ScanBytes : scan raw bytes and report results from ClamD
// using 'INSTREAM' command
func (d *ClamD) ScanBytes(b []byte) ([]*Result, error) {
	// check if chunk size is too big
	if len(b) > 1024 {
		return nil, fmt.Errorf("chunk size < %d bytes", 1024)
	}
	// spawn conn
	conn, err := d.spawnConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// start bytes in-stream
	if err = conn.Command("INSTREAM"); err != nil {
		return nil, err
	}
	// attempt to write chunk and return data
	if err = conn.Chunk(b); err != nil {
		return nil, err
	}
	// attempt to write EOF to end daemon reads
	if err = conn.EOF(); err != nil {
		return nil, err
	}
	return conn.Responses(), nil
}

//(*ClamD).ScanFile : Scan file or directory (recursively)
// with archive support enabled (a full path is required).
func (d *ClamD) ScanFile(path string) ([]*Result, error) {
	return d.command("SCAN "+path)
}

//(*ClamD).ScanRawFile : scan file or directory (recursively)
// with archive and special file support disabled (a full path is required).
func (d *ClamD) ScanRawFile(path string) ([]*Result, error) {
	return d.command("RAWSCAN "+path)
}


//(*ClamD).MultiScanFile : scan file in a standard way or scan directory (recursively)
// using multiple threads  (to make the scanning faster on SMP machines).
func (d *ClamD) MultiScanFile(path string) ([]*Result, error) {
	return d.command("MULTISCAN "+path)
}

//(*ClamD).ContScanFile : Scan file or directory (recursively)
// with archive support enabled and don’t stop the scanning when a virus is found.
func (d *ClamD) ContScanFile(path string) ([]*Result, error) {
	return d.command("MULTISCAN "+path)
}

//(*ClamD).ContScanFile : scan file or directory (recursively)
// with archive support enabled and don’t stop the scanning when a virus is found.
func (d *ClamD) AllMatchScanFile(path string) ([]*Result, error) {
	return d.command("MULTISCAN "+path)
}