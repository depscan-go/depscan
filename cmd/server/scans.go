package main

import "net"

// localOnly says whether addr accepts connections from this computer only.
// Only then does GET /scans list every scan.
func localOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
