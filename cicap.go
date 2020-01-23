package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"time"

	"github.com/imgurbot12/clamd"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	eicarRequest  []byte
	icapRespCode  = regexp.MustCompile(`^ICAP/1\.0 (\d+)`)
	icapRespFound = regexp.MustCompile(`^X-Infection-Found: .*Threat=(.*);`)
)

type IcapOptions struct {
	Host    string `json:"host"`
	Port    string `json:"port"`
	Service string `json:"service"`
}

type IcapChecker struct {
	opts IcapOptions

	promIcapUp                 *prometheus.Desc
	promIcapEicarDetected      *prometheus.Desc
	promIcapEicarDetectionTime *prometheus.Desc
}

func NewIcapChecker(opts IcapOptions) *IcapChecker {
	if opts.Host == "" {
		opts.Host = "localhost"
	}
	if opts.Port == "" {
		opts.Port = "1344"
	}
	if opts.Service == "" {
		opts.Service = "squidclamav?allow204=on&force=on&sizelimit=off&mode=simple"
	}
	return &IcapChecker{
		opts: opts,
		promIcapUp: prometheus.NewDesc(
			"clamav_icap_up",
			"connection to clamd is successful",
			[]string{}, // TODO label? "version"},
			nil),
		promIcapEicarDetected: prometheus.NewDesc(
			"clamav_icap_eicar_detected",
			"successfully detected eicar test stream",
			[]string{},
			nil),
		promIcapEicarDetectionTime: prometheus.NewDesc(
			"clamav_icap_eicar_detection_time_seconds",
			"eicar test stream detection time",
			[]string{},
			nil),
	}
}

func (c *IcapChecker) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.promIcapUp
	ch <- c.promIcapEicarDetected
	ch <- c.promIcapEicarDetectionTime
}

func (c *IcapChecker) Collect(ch chan<- prometheus.Metric) {
	up := 1.0
	eicarDetected, eicarTime, err := c.collectEicar()
	if err != nil {
		up = 0
	}
	ch <- prometheus.MustNewConstMetric(
		c.promIcapUp,
		prometheus.GaugeValue,
		up,
		// TODO version label?
	)
	ch <- prometheus.MustNewConstMetric(
		c.promIcapEicarDetected,
		prometheus.GaugeValue,
		float64(eicarDetected),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promIcapEicarDetectionTime,
		prometheus.GaugeValue,
		float64(eicarTime.Seconds()),
	)
}

func (c *IcapChecker) collectEicar() (detected int, elapsed time.Duration, err error) {
	hostPort := net.JoinHostPort(c.opts.Host, c.opts.Port)
	var addr *net.TCPAddr
	if addr, err = net.ResolveTCPAddr("tcp", hostPort); err != nil {
		return
	}

	start := time.Now()
	var conn *net.TCPConn
	if conn, err = net.DialTCP("tcp", nil, addr); err != nil {
		return
	}

	req := bytes.NewBuffer(nil) // TODO pre-alloc correct size
	req.WriteString(fmt.Sprintf("RESPMOD icap://%s/%s ICAP/1.0\r\n", hostPort, c.opts.Service))
	req.WriteString(fmt.Sprintf("Host: %s", hostPort))
	req.WriteString("User-Agent: clamav-exporter\r\n")
	// see Allow: 204 in https://tools.ietf.org/html/rfc3507#section-4.6
	req.WriteString("Allow: 204\r\n")
	req.WriteString("\r\n")
	req.Write(clamd.EICAR)
	reqLen := req.Len()

	var n int64
	n, err = io.Copy(conn, req)
	if err != nil {
		return
	}
	if n != int64(reqLen) {
		err = errors.New("partial write of eicar request")
		return
	}

	err = conn.CloseWrite()
	if err != nil {
		return
	}

	var res []byte
	if res, err = ioutil.ReadAll(conn); err != nil {
		return
	}

	elapsed = time.Since(start)
	detected = parseResult(res)

	return
}

func parseResult(icapRes []byte) int {
	log.Printf("icap response:\n%v", string(icapRes))
	return -10
}
