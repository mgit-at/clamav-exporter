// Copyright (c) 2020 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package main

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/imgurbot12/clamd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shenwei356/util/bytesize"
)

const (
	clamdDBTimeFormat = "Mon Jan 2 15:04:05 2006"
)

var (
	clamdVersionRegexp = regexp.MustCompile(`^ClamAV (?P<clamav_version>.*?)/(?P<db_version>.*?)/(?P<db_date>.*?)$`)

	clamdStatsQueueRegexp   = regexp.MustCompile(`^(\d+)\s+item.*$`)
	clamdStatsThreadsRegexp = regexp.MustCompile(`^live\s+(\d+)\s+idle\s+(\d+)\s+max\s+(\d+)\s+idle-timeout\s+(\d+)$`)
	clamdStatsMemRegexp     = regexp.MustCompile(`^heap\s+(\d+.\d+\w)\s+mmap\s+(\d+.\d+\w)\s+used\s+(\d+.\d+\w)\s+free\s+(\d+.\d+\w)\s+releasable\s+(\d+.\d+\w)` +
		`\s+pools\s+(\d+)\s+pools_used\s+(\d+.\d+\w)\s+pools_total\s+(\d+.\d+\w)$`)
)

type ClamDOptions struct {
	URL string `json:"url"`
}

type ClamDChecker struct {
	opts ClamDOptions

	promClamDUp                 *prometheus.Desc
	promClamDDBVersion          *prometheus.Desc
	promClamDDBTime             *prometheus.Desc
	promClamDStatsQueueLength   *prometheus.Desc
	promClamDStatsThreadsLive   *prometheus.Desc
	promClamDStatsThreadsIdle   *prometheus.Desc
	promClamDStatsThreadsMax    *prometheus.Desc
	promClamDStatsMemHeap       *prometheus.Desc
	promClamDStatsMemMMap       *prometheus.Desc
	promClamDStatsMemUsed       *prometheus.Desc
	promClamDStatsMemFree       *prometheus.Desc
	promClamDStatsMemReleasable *prometheus.Desc
	promClamDStatsMemPools      *prometheus.Desc
	promClamDStatsMemPoolsUsed  *prometheus.Desc
	promClamDStatsMemPoolsTotal *prometheus.Desc
	promClamDEicarDetected      *prometheus.Desc
	promClamDEicarDetectionTime *prometheus.Desc
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
			"clamav_clamd_db_version_info",
			"version of currently used virus definition database",
			[]string{},
			nil),
		promClamDDBTime: prometheus.NewDesc(
			"clamav_clamd_db_time_info",
			"unix epoch timestamp of currently used virus definition database",
			[]string{},
			nil),
		promClamDStatsQueueLength: prometheus.NewDesc(
			"clamav_clamd_stats_queue_length",
			"mumber of items in clamd queue",
			[]string{},
			nil),
		promClamDStatsThreadsLive: prometheus.NewDesc(
			"clamav_clamd_stats_threads_live",
			"number of busy clamd threads",
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
		promClamDStatsMemHeap: prometheus.NewDesc(
			"clamav_clamd_stats_mem_heap_bytes",
			"amount of memory used by libc from the heap",
			[]string{},
			nil),
		promClamDStatsMemMMap: prometheus.NewDesc(
			"clamav_clamd_stats_mem_mmap_bytes",
			"amount of memory used by libc from mmap-allocated memory",
			[]string{},
			nil),
		promClamDStatsMemUsed: prometheus.NewDesc(
			"clamav_clamd_stats_mem_used_bytes",
			"amount of useful memory allocated by libc",
			[]string{},
			nil),
		promClamDStatsMemFree: prometheus.NewDesc(
			"clamav_clamd_stats_mem_free_bytes",
			"amount of memory allocated by libc, that can't be freed due to fragmentation",
			[]string{},
			nil),
		promClamDStatsMemReleasable: prometheus.NewDesc(
			"clamav_clamd_stats_mem_realeasable_bytes",
			"amount of memory that can be reclaimed by libc",
			[]string{},
			nil),
		promClamDStatsMemPools: prometheus.NewDesc(
			"clamav_clamd_stats_mem_pools",
			"number of mmap regions allocated by clamd's memory pool allocator",
			[]string{},
			nil),
		promClamDStatsMemPoolsUsed: prometheus.NewDesc(
			"clamav_clamd_stats_mem_pools_used_bytes",
			"amount of memory used by clamd's memory pool allocator",
			[]string{},
			nil),
		promClamDStatsMemPoolsTotal: prometheus.NewDesc(
			"clamav_clamd_stats_mem_pools_total_bytes",
			"total amount of memory allocated by clamd's memory pool allocator",
			[]string{},
			nil),
		promClamDEicarDetected: prometheus.NewDesc(
			"clamav_clamd_eicar_detected",
			"successfully detected eicar test stream",
			[]string{},
			nil),
		promClamDEicarDetectionTime: prometheus.NewDesc(
			"clamav_clamd_eicar_detection_time_seconds",
			"eicar test stream detection time",
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
	ch <- c.promClamDStatsMemHeap
	ch <- c.promClamDStatsMemMMap
	ch <- c.promClamDStatsMemUsed
	ch <- c.promClamDStatsMemFree
	ch <- c.promClamDStatsMemReleasable
	ch <- c.promClamDStatsMemPools
	ch <- c.promClamDStatsMemPoolsUsed
	ch <- c.promClamDStatsMemPoolsTotal
	ch <- c.promClamDEicarDetected
	ch <- c.promClamDEicarDetectionTime
}

func (c *ClamDChecker) Collect(ch chan<- prometheus.Metric) {
	up := 1.0
	version, dbVersion, dbTime, err := c.collectVersion()
	if err != nil {
		up = 0.0
		dbVersion = math.NaN()
		dbTime = math.NaN()
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
		dbVersion,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDDBTime,
		prometheus.GaugeValue,
		dbTime,
	)

	stats, _ := c.collectStats()
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsQueueLength,
		prometheus.GaugeValue,
		stats.Queue.Length,
	)

	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsThreadsLive,
		prometheus.GaugeValue,
		stats.Threads.Live,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsThreadsIdle,
		prometheus.GaugeValue,
		stats.Threads.Idle,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsThreadsMax,
		prometheus.GaugeValue,
		stats.Threads.Max,
	)

	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemHeap,
		prometheus.GaugeValue,
		stats.Mem.Heap,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemMMap,
		prometheus.GaugeValue,
		stats.Mem.MMap,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemUsed,
		prometheus.GaugeValue,
		stats.Mem.Used,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemFree,
		prometheus.GaugeValue,
		stats.Mem.Free,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemReleasable,
		prometheus.GaugeValue,
		stats.Mem.Releasable,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemPools,
		prometheus.GaugeValue,
		stats.Mem.Pools.Count,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemPoolsUsed,
		prometheus.GaugeValue,
		stats.Mem.Pools.Used,
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemPoolsTotal,
		prometheus.GaugeValue,
		stats.Mem.Pools.Total,
	)

	eicarDetected, eicarTime, _ := c.collectEicar()
	ch <- prometheus.MustNewConstMetric(
		c.promClamDEicarDetected,
		prometheus.GaugeValue,
		float64(eicarDetected),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDEicarDetectionTime,
		prometheus.GaugeValue,
		eicarTime,
	)
}

func (c *ClamDChecker) collectVersion() (version string, dbVersion, dbTime float64, err error) {
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

	var dbVersionValue int
	if dbVersionValue, err = strconv.Atoi(matches[2]); err != nil {
		return
	}
	dbVersion = float64(dbVersionValue)

	// clamd reports the db time in local time, for now we assume that the system timezone of the host clamd
	// is running on is the same as on the host the exporter is running on, TODO: add a config option for this
	var dbTimeValue time.Time
	if dbTimeValue, err = time.ParseInLocation(clamdDBTimeFormat, matches[3], time.Local); err != nil {
		return
	}
	dbTime = float64(dbTimeValue.Unix())
	return
}

type clamdStats struct {
	Queue struct {
		Length float64
	}
	Threads struct {
		Live float64
		Idle float64
		Max  float64
	}
	Mem struct {
		Heap       float64
		MMap       float64
		Used       float64
		Free       float64
		Releasable float64

		Pools struct {
			Count float64
			Used  float64
			Total float64
		}
	}
}

func cvtInt(number string) float64 {
	v, err := strconv.Atoi(number)
	if err != nil {
		return math.NaN()
	}
	return float64(v)
}

func cvtByteSize(number string) float64 {
	v, err := bytesize.Parse([]byte(number))
	if err != nil {
		return math.NaN()
	}
	return float64(v)
}

func (c *ClamDChecker) collectStats() (stats clamdStats, err error) {
	stats.Queue.Length = math.NaN()
	stats.Threads.Live = math.NaN()
	stats.Threads.Idle = math.NaN()
	stats.Threads.Max = math.NaN()
	stats.Mem.Heap = math.NaN()
	stats.Mem.MMap = math.NaN()
	stats.Mem.Used = math.NaN()
	stats.Mem.Free = math.NaN()
	stats.Mem.Releasable = math.NaN()
	stats.Mem.Pools.Count = math.NaN()
	stats.Mem.Pools.Used = math.NaN()
	stats.Mem.Pools.Total = math.NaN()

	var cl *clamd.ClamD
	if cl, err = clamd.NewClamd(c.opts.URL); err != nil {
		return
	}

	var s *clamd.ClamDStats
	if s, err = cl.Stats(); err != nil {
		return
	}

	q := clamdStatsQueueRegexp.FindStringSubmatch(s.Queue)
	if len(q) == 2 {
		stats.Queue.Length = cvtInt(q[1])
	}

	t := clamdStatsThreadsRegexp.FindStringSubmatch(s.Threads)
	if len(t) == 5 {
		stats.Threads.Live = cvtInt(t[1])
		stats.Threads.Idle = cvtInt(t[2])
		stats.Threads.Max = cvtInt(t[3])
	}

	m := clamdStatsMemRegexp.FindStringSubmatch(s.Memstats)
	if len(m) == 9 {
		stats.Mem.Heap = cvtByteSize(m[1])
		stats.Mem.MMap = cvtByteSize(m[2])
		stats.Mem.Used = cvtByteSize(m[3])
		stats.Mem.Free = cvtByteSize(m[4])
		stats.Mem.Releasable = cvtByteSize(m[5])
		stats.Mem.Pools.Count = cvtInt(m[6])
		stats.Mem.Pools.Used = cvtByteSize(m[7])
		stats.Mem.Pools.Total = cvtByteSize(m[8])
	}

	return
}

func (c *ClamDChecker) collectEicar() (detected int, elapsed float64, err error) {
	elapsed = math.NaN()

	var cl *clamd.ClamD
	if cl, err = clamd.NewClamd(c.opts.URL); err != nil {
		return
	}

	start := time.Now()
	var results []*clamd.Result
	results, err = cl.ScanBytes(clamd.EICAR)
	elapsed = time.Since(start).Seconds()
	if err != nil || len(results) != 1 {
		return
	}
	if results[0].Status == clamd.RES_FOUND {
		detected = 1
	}
	return
}
