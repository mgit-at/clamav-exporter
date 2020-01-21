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
)

const (
	clamdDBTimeFormat = "Mon Jan 2 15:04:05 2006"
)

var (
	clamdVersionRegexp = regexp.MustCompile(`ClamAV (?P<clamav_version>.*?)/(?P<db_version>.*?)/(?P<db_date>.*?)$`)
)

type ClamDOptions struct {
	URL string `json:"url"`
}

type ClamDChecker struct {
	opts ClamDOptions

	promClamDUp        *prometheus.Desc
	promClamDDBVersion *prometheus.Desc
	promClamDDBTime    *prometheus.Desc
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
	}
}

func (c *ClamDChecker) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.promClamDUp
	ch <- c.promClamDDBVersion
	ch <- c.promClamDDBTime
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
