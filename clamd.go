// Copyright (c) 2020 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package main

import (
	"errors"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/imgurbot12/clamd"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	clamdDBTimeFormat = "Mon Jan 2 15:04:05 2006"
)

var (
	clamdVersionRegexp = regexp.MustCompile(`^ClamAV (?P<clamav_version>.*?)/(?P<db_version>.*?)/(?P<db_date>.*?)$`)

	clamdStatsQueueRegexp   = regexp.MustCompile(`^(\d+)\s+item.*$`)
	clamdStatsThreadsRegexp = regexp.MustCompile(`^live\s+(\d+)\s+idle\s+(\d+)\s+max\s+(\d+)\s+idle-timeout\s+(\d+)$`)
)

type ClamDOptions struct {
	URL string `json:"url"`
}

type ClamDChecker struct {
	opts ClamDOptions

	promClamDUp               *prometheus.Desc
	promClamDDBVersion        *prometheus.Desc
	promClamDDBTime           *prometheus.Desc
	promClamDStatsQueueLength *prometheus.Desc
	promClamDStatsThreadsLive *prometheus.Desc
	promClamDStatsThreadsIdle *prometheus.Desc
	promClamDStatsThreadsMax  *prometheus.Desc
}

func NewClamDChecker(opts ClamDOptions) *ClamDChecker {
	return &ClamDChecker{
		opts: opts,
		promClamDUp: prometheus.NewDesc(
			"clamav_clamd_up",
			"connection to clamd is successful",
			[]string{"version"},
			nil),
		promClamDDBVersion: prometheus.NewDesc(
			"clamav_clamd_db_version",
			"version of currently used virus definition DB",
			[]string{},
			nil),
		promClamDDBTime: prometheus.NewDesc(
			"clamav_clamd_db_time",
			"timestamp of currently used virus definition DB",
			[]string{},
			nil),
		promClamDStatsQueueLength: prometheus.NewDesc(
			"clamav_clamd_stats_queue_length",
			"mumber of items in clamd queue",
			[]string{},
			nil),
		promClamDStatsThreadsLive: prometheus.NewDesc(
			"clamav_clamd_stats_threads_live",
			"number of  busy clamd threads",
			[]string{},
			nil),
		promClamDStatsThreadsIdle: prometheus.NewDesc(
			"clamav_clamd_stats_threads_idle",
			"number of idle clamd threads",
			[]string{},
			nil),
		promClamDStatsThreadsMax: prometheus.NewDesc(
			"clamav_clamd_stats_threads_max",
			"maximum number of clamd threads",
			[]string{},
			nil),
	}
}

func (c *ClamDChecker) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.promClamDUp
	ch <- c.promClamDDBVersion
	ch <- c.promClamDDBTime
	ch <- c.promClamDStatsQueueLength
	ch <- c.promClamDStatsThreadsLive
	ch <- c.promClamDStatsThreadsIdle
	ch <- c.promClamDStatsThreadsMax
}

func (c *ClamDChecker) Collect(ch chan<- prometheus.Metric) {
	up := 1.0
	version, dbVersion, dbTime, err := c.collectVersion()
	if err != nil {
		up = 0.0
	}

	ch <- prometheus.MustNewConstMetric(
		c.promClamDUp,
		prometheus.GaugeValue,
		up,
		version,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDDBVersion,
		prometheus.GaugeValue,
		float64(dbVersion),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDDBTime,
		prometheus.GaugeValue,
		float64(dbTime.Unix()),
	)

	stats, _ := c.collectStats()
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsQueueLength,
		prometheus.GaugeValue,
		float64(stats.QueueLength),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsThreadsLive,
		prometheus.GaugeValue,
		float64(stats.Threads.Live),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsThreadsIdle,
		prometheus.GaugeValue,
		float64(stats.Threads.Idle),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsThreadsMax,
		prometheus.GaugeValue,
		float64(stats.Threads.Max),
	)
}

func (c *ClamDChecker) collectVersion() (version string, dbVersion int, dbTime time.Time, err error) {
	var cl *clamd.ClamD
	if cl, err = clamd.NewClamd(c.opts.URL); err != nil {
		return
	}

	var v string
	if v, err = cl.Version(); err != nil {
		return
	}
	matches := clamdVersionRegexp.FindStringSubmatch(v)
	if len(matches) != 4 {
		err = errors.New("got invalid clamd version string")
		return
	}

	version = matches[1]

	if dbVersion, err = strconv.Atoi(matches[2]); err != nil {
		return
	}

	if dbTime, err = time.Parse(clamdDBTimeFormat, matches[3]); err != nil {
		return
	}

	return
}

type clamdStats struct {
	QueueLength int
	Threads     struct {
		Live int
		Idle int
		Max  int
	}
}

func (c *ClamDChecker) collectStats() (stats clamdStats, err error) {
	stats.QueueLength = -1
	stats.Threads.Live = -1
	stats.Threads.Idle = -1
	stats.Threads.Max = -1

	var cl *clamd.ClamD
	if cl, err = clamd.NewClamd(c.opts.URL); err != nil {
		return
	}

	var s *clamd.ClamDStats
	if s, err = cl.Stats(); err != nil {
		return
	}
	log.Printf("%#v", s)

	q := clamdStatsQueueRegexp.FindStringSubmatch(s.Queue)
	if len(q) == 2 {
		stats.QueueLength, _ = strconv.Atoi(q[1])
	}

	t := clamdStatsThreadsRegexp.FindStringSubmatch(s.Threads)
	if len(t) == 5 {
		stats.Threads.Live, _ = strconv.Atoi(t[1])
		stats.Threads.Idle, _ = strconv.Atoi(t[2])
		stats.Threads.Max, _ = strconv.Atoi(t[3])
	}

	return

	// 	statsData := clamdStats{}
	// 	if inum,err := strconv.Atoi(stats.Pools); err == nil {
	// 		statsData.Pools = inum
	// 	}
	// 	statsData.State = strings.Replace(stats.State,"STATE: ","",-1)
	// 	if inum,err := strconv.Atoi(getNumber.FindString(stats.Queue)); err == nil {
	// 		statsData.Queue = inum
	// 	}

	// 	mem := getNumber.FindAllString(stats.Memstats,-1)
	// 	memLen := len(mem)
	// 	if memLen >= 4 {
	// 		if inum, err := strconv.ParseFloat(mem[0], 32 ); err == nil {
	// 			statsData.Memory.Heap = inum * 1024.0 * 1024.0
	// 		}
	// 		if inum, err := strconv.ParseFloat(mem[1], 32 ); err == nil {
	// 			statsData.Memory.Mmap = inum * 1024 * 1024
	// 		}
	// 		if inum, err := strconv.ParseFloat(mem[2], 32); err == nil {
	// 			statsData.Memory.Used = inum * 1024 * 1024
	// 		}
	// 		if inum, err := strconv.ParseFloat(mem[3], 32); err == nil {
	// 			statsData.Memory.Free = inum * 1024 * 1024
	// 		}
	// 		poolcount, _ := strconv.Atoi(mem[5])
	// 		pools := make([]clamdStatsMemPool,poolcount)
	// 		for i := 0; i < poolcount; i++ {
	// 			idx := 6 + i * 2
	// 			if inum,err := strconv.ParseFloat(mem[idx], 32 ); err == nil {
	// 				pools[i].Used = inum * 1024 * 1024
	// 			}
	// 			if inum,err := strconv.ParseFloat( mem[idx + 1], 32); err == nil {
	// 				pools[i].Total = inum * 1024 * 1024
	// 			}
	// 		}
	// 		statsData.Memory.Pools = pools
	// 	}
	// 	clamd_stats.Stats = statsData

	// 	return clamd_stats

}

// func getclamdStats(url string) (*clamdData) {

// 	getNumber := regexp.MustCompile("[.0-9]+")

// 	c := clamd.NewClamd(url)
// 	clamd_stats := &clamdData{}
// 	clamd_stats.Err = ""

// 	start := time.Now()
// 	err := c.Ping()
// 	elapsed := time.Since(start)
// 	if err != nil {
// 		clamd_stats.Err = err.Error()
// 		return clamd_stats
// 	}
// 	clamd_stats.Ping = elapsed

// 	reader := bytes.NewReader(clamd.EICAR)
// 	chanFoo := make(chan bool)

// 	start = time.Now()
// 	_, err = c.ScanStream(reader, chanFoo)
// 	elapsed = time.Since(start)
// 	if err != nil {
// 		clamd_stats.Err = err.Error()
// 		return clamd_stats
// 	}
// 	clamd_stats.EicarScan = elapsed

// }
