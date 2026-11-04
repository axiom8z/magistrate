//go:build !windows

package main

import "time"

var clockStart = time.Now()

func nowNS() int64 { return int64(time.Since(clockStart)) }
