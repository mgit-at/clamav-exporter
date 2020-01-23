// Copyright (c) 2020 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package main

import (
	"errors"
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
			"clamav_clamd_stats_mem_used",
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
		float64(stats.Queue.Length),
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

	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemHeap,
		prometheus.GaugeValue,
		float64(stats.Mem.Heap),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemMMap,
		prometheus.GaugeValue,
		float64(stats.Mem.MMap),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemUsed,
		prometheus.GaugeValue,
		float64(stats.Mem.Used),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemFree,
		prometheus.GaugeValue,
		float64(stats.Mem.Free),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemReleasable,
		prometheus.GaugeValue,
		float64(stats.Mem.Releasable),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemPools,
		prometheus.GaugeValue,
		float64(stats.Mem.Pools.Count),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemPoolsUsed,
		prometheus.GaugeValue,
		float64(stats.Mem.Pools.Used),
	)
	ch <- prometheus.MustNewConstMetric(
		c.promClamDStatsMemPoolsTotal,
		prometheus.GaugeValue,
		float64(stats.Mem.Pools.Total),
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
		float64(eicarTime.Seconds()),
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

	// clamd reports the db time in local time, for now we assume that the system timezone of the host clamd
	// is running on is the same as on the host the exporter is running on, TODO: add a config option for this
	if dbTime, err = time.ParseInLocation(clamdDBTimeFormat, matches[3], time.Local); err != nil {
		return
	}

	return
}

type clamdStats struct {
	Queue struct {
		Length int
	}
	Threads struct {
		Live int
		Idle int
		Max  int
	}
	Mem struct {
		Heap       bytesize.ByteSize
		MMap       bytesize.ByteSize
		Used       bytesize.ByteSize
		Free       bytesize.ByteSize
		Releasable bytesize.ByteSize

		Pools struct {
			Count int
			Used  bytesize.ByteSize
			Total bytesize.ByteSize
		}
	}
}

func (c *ClamDChecker) collectStats() (stats clamdStats, err error) {
	stats.Queue.Length = -1
	stats.Threads.Live = -1
	stats.Threads.Idle = -1
	stats.Threads.Max = -1
	stats.Mem.Pools.Count = -1

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
		stats.Queue.Length, _ = strconv.Atoi(q[1])
	}

	t := clamdStatsThreadsRegexp.FindStringSubmatch(s.Threads)
	if len(t) == 5 {
		stats.Threads.Live, _ = strconv.Atoi(t[1])
		stats.Threads.Idle, _ = strconv.Atoi(t[2])
		stats.Threads.Max, _ = strconv.Atoi(t[3])
	}

	m := clamdStatsMemRegexp.FindStringSubmatch(s.Memstats)
	if len(m) == 9 {
		stats.Mem.Heap, _ = bytesize.Parse([]byte(m[1]))
		stats.Mem.MMap, _ = bytesize.Parse([]byte(m[2]))
		stats.Mem.Used, _ = bytesize.Parse([]byte(m[3]))
		stats.Mem.Free, _ = bytesize.Parse([]byte(m[4]))
		stats.Mem.Releasable, _ = bytesize.Parse([]byte(m[5]))
		stats.Mem.Pools.Count, _ = strconv.Atoi(m[6])
		stats.Mem.Pools.Used, _ = bytesize.Parse([]byte(m[7]))
		stats.Mem.Pools.Total, _ = bytesize.Parse([]byte(m[8]))
	}

	return
}

func (c *ClamDChecker) collectEicar() (detected int, elapsed time.Duration, err error) {
	var cl *clamd.ClamD
	if cl, err = clamd.NewClamd(c.opts.URL); err != nil {
		return
	}

	start := time.Now()
	var results []*clamd.Result
	results, err = cl.ScanBytes(clamd.EICAR)
	elapsed = time.Since(start)
	if err != nil || len(results) != 1 {
		return
	}
	if results[0].Status == clamd.RES_FOUND {
		detected = 1
	}
	return
}
