package clamd

import (
	"fmt"
)

/* Variables */

//InStream : streaming object to pass raw bytes for ClamD to evaluate
type InStream struct {
	chSize  int   // maximum chunk-size allowed for one transaction
	conn    *clamdConn
}

/* Methods */

//(*InStream).Write : write chunk of data to stream
func (s *InStream) Write(b []byte) error {
	if len(b) > s.chSize {
		return fmt.Errorf("chunk size < %d bytes", s.chSize)
	}
	return s.conn.Chunk(b)
}

//(*InStream).Finish : return responses for writen chunks of data
func (s *InStream) Finish() ([]*Result, error) {
	if err := s.conn.EOF(); err != nil {
		return nil, err
	}
	defer s.conn.Close()
	return s.conn.Responses(), nil
}