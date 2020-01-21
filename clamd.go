// Copyright (c) 2020 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package main

import (
	"log"

	"github.com/imgurbot12/clamd"
	"github.com/prometheus/client_golang/prometheus"
)

type ClamDOptions struct {
	URL string `json:"url"`
}

type ClamDChecker struct {
	opts ClamDOptions

	promClamDDBTime *prometheus.Desc
}

func NewClamDChecker(opts ClamDOptions) *ClamDChecker {
	return &ClamDChecker{
		opts: opts,
		promClamDDBTime: prometheus.NewDesc(
			"clamav_clamd_db_time",
			"timestamp of currently used virus definition DB",
			[]string{},
			nil),
	}
}

func (c *ClamDChecker) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.promClamDDBTime
}

func (c *ClamDChecker) Collect(ch chan<- prometheus.Metric) {
	epoch, err := c.collectDBTime()
	if err != nil {
		log.Println("failed to get DB time", err)
		// TODO maybe write NIL/ERROR into gauge?
		return
	}

	ch <- prometheus.MustNewConstMetric(
		c.promClamDDBTime,
		prometheus.GaugeValue,
		epoch,
	)
}

func (c *ClamDChecker) collectDBTime() (float64, error) {
	cl, err := clamd.NewClamd(c.opts.URL)
	if err != nil {
		return 0, err
	}

	v, err := cl.Version()
	if err != nil {
		return 0, err
	}

	log.Printf("got version: %s", v)
	return 0, nil
}
