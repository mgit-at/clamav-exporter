// Copyright (c) 2020 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Config struct {
	Listen string `json:"listen"`
	ClamD  struct {
		Enable bool `json:"enable"`
		ClamDOptions
	} `json:"clamd"`
}

func run() error {
	var (
		flagConfig = flag.String("config", "config.json", "configuration file")
	)
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		return fmt.Errorf("invalid number of arguments")
	}

	cfgFile, err := os.Open(*flagConfig)
	if err != nil {
		return fmt.Errorf("failed to open config %q: %v", *flagConfig, err)
	}
	defer cfgFile.Close()

	var cfg Config
	if err := json.NewDecoder(cfgFile).Decode(&cfg); err != nil {
		return fmt.Errorf("failed to decode config %q: %v", *flagConfig, err)
	}

	if cfg.ClamD.Enable {
		log.Println("enabling clamd checker")
		c := NewClamDChecker(cfg.ClamD.ClamDOptions)
		if err := prometheus.Register(c); err != nil {
			return fmt.Errorf("failed to register clamd checker: %v", err)
		}

	}

	if cfg.Listen == "" {
		cfg.Listen = ":9328"
	}
	listen, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("failed to listen at %q: %v", cfg.Listen, err)
	}
	defer listen.Close()
	log.Println("listening on", listen.Addr())

	http.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Minute,
	}
	if err := srv.Serve(listen); err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}
