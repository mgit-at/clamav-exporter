package clamd

import (
	"net"
	"fmt"
	"regexp"
	"strings"
	"bufio"
	"strconv"
)

/* Variables */

//Result : response object from ClamD after command
// has been executed
type Result struct {
	raw         string
	Description string
	Path        string
	Hash        string
	Size        int
	Status      string
}

//clamdConn : wrapped net.Conn to allow for messaging
// between daemon and current process
type clamdConn struct {
	net.Conn
}

const (
	RES_OK          = "OK"
	RES_FOUND       = "FOUND"
	RES_ERROR       = "ERROR"
	RES_PARSE_ERROR = "PARSE ERROR"
)
var (
	resRGXRaw = `^(?P<path>[^:]+): ((?P<desc>[^:]+)(\((?P<vhash>([^:]+)):(?P<vsize>\d+)\))? )?(?P<status>FOUND|ERROR|OK)$`
	resRGX    = regexp.MustCompile(resRGXRaw)

	bEOF = []byte{0, 0, 0, 0}
)

/* Methods */

//(*Result).parse : parse raw ClamD response into struct
func (r *Result) parse(line string){
	r.raw = line
	// attempt to find matches for regex
	var matches []string
	if matches = resRGX.FindStringSubmatch(line); len(matches) == 0 {
		r.Description = "Regex had no matches"
		r.Status = RES_PARSE_ERROR
		return
	}
	for i, name := range resRGX.SubexpNames() {
		switch name {
		case "path":    r.Path = matches[i]
		case "desc":    r.Description = matches[i]
		case "virhash": r.Hash = matches[i]
		case "virsize":
			if i, err := strconv.Atoi(matches[i]); err == nil {
				r.Size = i
			}
		case "status":
			switch matches[i] {
			case RES_OK:
			case RES_FOUND:
			case RES_ERROR:
				break
			default:
				r.Description = "invalid status field: " + matches[i]
				r.Status = RES_PARSE_ERROR
				return
			}
			r.Status = matches[i]
		}
	}
}

//(*clamdConn).Command: send command to ClamD via socket
func (c *clamdConn) Command(cmd string) error {
	_, err := fmt.Fprintf(*c, "n%s\n", cmd)
	return err
}

//(*clamdConn).EOF : send eof to ClamD via socket
func (c *clamdConn) EOF() error {
	_, err := c.Write(bEOF)
	return err
}

//(*clamdConn).Chunk : write chunk of data to ClamD
func (c *clamdConn) Chunk(data []byte) error {
	// write length of chunk to ClamD
	var dlen = len(data)
	_, err := c.Write([]byte{
		byte(dlen >> 24),
		byte(dlen >> 16),
		byte(dlen >> 8),
		byte(dlen >> 0),
	})
	if err != nil {
		return err
	}
	// write actual chunk to ClamD
	_, err = c.Write(data)
	return err
}

//(*clamdConn).Responses : return responses for previously sent command
func (c *clamdConn) Responses() []*Result {
	var (
		err     error
		line    string
		res     *Result
		results []*Result
		r           = bufio.NewReader(c)
	)
	for {
		// attempt to read line from reader
		if line, err = r.ReadString('\n'); err != nil {
			break
		}
		// attempt to parse result after trim-ing unneeded characters
		res = new(Result)
		res.parse(strings.TrimRight(line, " \t\r\n"))
		results = append(results, res)
	}
	return results
}
