// Copyright (c) 2020 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	versionTestStr = "ClamAV 0.102.1/25701/Mon Jan 20 12:41:43 2020"
	dbTimeEpoch    = int64(1579524103) // `date -d "Mon Jan 20 12:41:43 2020" -u +"%s"`

)

func TestParseVersion(t *testing.T) {
	r := require.New(t)
	matches := clamdVersionRegexp.FindStringSubmatch(versionTestStr)
	r.NotNil(matches)
	r.Len(matches, 4)
	r.Equal(matches[1], "0.102.1")
	r.Equal(matches[2], "25701")
	r.Equal(matches[3], "Mon Jan 20 12:41:43 2020")

	dbTime, err := time.ParseInLocation(clamdDBTimeFormat, matches[3], time.UTC)
	r.NoError(err)
	r.Equal(dbTime.Unix(), dbTimeEpoch)
}
