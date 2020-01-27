package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/imgurbot12/clamd"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	icapServerVersionRegexp   = regexp.MustCompile(`Server: C-ICAP/(.+?)\r\n`)
	icapRespCodeRegexp        = regexp.MustCompile(`ICAP/1\.0 (\d+)`)
	icapRespThreatFoundRegexp = regexp.MustCompile(`X-Infection-Found: .*Threat=(.*);`)
)

type IcapOptions struct {
	Host    string `json:"host"`
	Port    string `json:"port"`
	Service string `json:"service"`
}

type IcapChecker struct {
	opts IcapOptions

	promIcapUp                 *prometheus.Desc
	promIcapEicarIcapCode      *prometheus.Desc
	promIcapEicarDetected      *prometheus.Desc
	promIcapEicarDetectionTime *prometheus.Desc
	promIcapHelloOK            *prometheus.Desc
	promIcapHelloOKTime        *prometheus.Desc
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
			[]string{"version"},
			nil),
		promIcapEicarIcapCode: prometheus.NewDesc(
			"clamav_icap_eicar_icap_code",
			"ICAP result code for eicar test stream",
			[]string{},
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
		promIcapHelloOK: prometheus.NewDesc(
			"clamav_icap_hello_ok",
			"correctly identified hello as non-threatening",
			[]string{},
			nil),
		promIcapHelloOKTime: prometheus.NewDesc(
			"clamav_icap_hello_ok_time_seconds",
			"unthreatening hello test stream detection time",
			[]string{},
			nil),
	}
}

func (c *IcapChecker) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.promIcapUp
	ch <- c.promIcapEicarIcapCode
	ch <- c.promIcapEicarDetected
	ch <- c.promIcapEicarDetectionTime
	ch <- c.promIcapHelloOK
	ch <- c.promIcapHelloOKTime
}

func (c *IcapChecker) Collect(ch chan<- prometheus.Metric) {
	up := 1.0
	icapServerVersion, eicarIcapCode, eicarDetected, eicarTime, err := c.collectEicar()
	if err != nil {
		up = 0
	}
	ch <- prometheus.MustNewConstMetric(
		c.promIcapUp,
		prometheus.GaugeValue,
		up,
		icapServerVersion,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promIcapEicarIcapCode,
		prometheus.GaugeValue,
		float64(eicarIcapCode),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promIcapEicarDetected,
		prometheus.GaugeValue,
		float64(eicarDetected),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promIcapEicarDetectionTime,
		prometheus.GaugeValue,
		eicarTime,
	)

	helloOK, helloTime := c.collectHello()

	ch <- prometheus.MustNewConstMetric(
		c.promIcapHelloOK,
		prometheus.GaugeValue,
		float64(helloOK),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promIcapHelloOKTime,
		prometheus.GaugeValue,
		helloTime,
	)
}

func (c *IcapChecker) collectEicar() (icapServerVersion string, icapCode, threatDetected int, threatElapsed float64, err error) {
	return c.testIcap(clamd.EICAR)
}

func (c *IcapChecker) collectHello() (helloOK int, helloElapsed float64) {
	var err error
	var helloIsThreat int
	_, _, helloIsThreat, helloElapsed, err = c.testIcap([]byte("I am a totally legit non-threatening Hello message from The Beyond!"))
	if err != nil {
		return
	}
	if helloIsThreat == 0 {
		helloOK = 1
	}
	return
}

func (c *IcapChecker) testIcap(data []byte) (icapServerVersion string, icapCode, detected int, elapsed float64, err error) {
	elapsed = math.NaN()

	hostPort := net.JoinHostPort(c.opts.Host, c.opts.Port)
	var addr *net.TCPAddr
	if addr, err = net.ResolveTCPAddr("tcp", hostPort); err != nil {
		return
	}

	start := time.Now()
	defer func() {
		elapsed = time.Since(start).Seconds()
	}()

	var conn *net.TCPConn
	if conn, err = net.DialTCP("tcp", nil, addr); err != nil {
		return
	}
	defer conn.Close()

	req := bytes.NewBuffer(nil) // TODO pre-alloc correct size
	req.WriteString(fmt.Sprintf("RESPMOD icap://%s/%s ICAP/1.0\r\n", hostPort, c.opts.Service))
	req.WriteString(fmt.Sprintf("Host: %s\r\n", hostPort))
	req.WriteString("User-Agent: clamav-exporter\r\n")
	// see Allow: 204 in https://tools.ietf.org/html/rfc3507#section-4.6
	req.WriteString("Allow: 204\r\n")
	httpHeader := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(clamd.EICAR))
	req.WriteString(fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(httpHeader)))
	req.WriteString("\r\n")
	req.WriteString(httpHeader)

	req.WriteString(fmt.Sprintf("%x\r\n", len(data)))
	req.Write(data)
	req.WriteString("\r\n")
	req.WriteString("0; ieof\r\n\r\n")

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

	icapServerVersion, icapCode, detected = parseIcapResult(res)
	return
}

func parseIcapResult(icapRes []byte) (serverVersion string, code, found int) {
	code = -1

	v := icapServerVersionRegexp.FindSubmatch(icapRes)
	if len(v) == 2 {
		serverVersion = string(v[1])
	}
	c := icapRespCodeRegexp.FindSubmatch(icapRes)
	if len(c) == 2 {
		code, _ = strconv.Atoi(string(c[1]))
	}
	t := icapRespThreatFoundRegexp.FindSubmatch(icapRes)
	if len(t) == 2 {
		found = 1
	}
	return
}
