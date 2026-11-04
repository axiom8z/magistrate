//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	queryCounter   = kernel32.NewProc("QueryPerformanceCounter")
	queryFrequency = kernel32.NewProc("QueryPerformanceFrequency")
	counterHz      = readFrequency()
)

func readFrequency() int64 {
	var hz int64
	queryFrequency.Call(uintptr(unsafe.Pointer(&hz)))
	return hz
}

// nowNS reads QueryPerformanceCounter, because time.Now only moves on timer ticks here (DESIGN section
// 8). Dividing first keeps the multiplication from overflowing on a machine that has been up for long.
func nowNS() int64 {
	var ticks int64
	syscall.SyscallN(queryCounter.Addr(), uintptr(unsafe.Pointer(&ticks)))
	return ticks/counterHz*1e9 + ticks%counterHz*1e9/counterHz
}
