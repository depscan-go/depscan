// TRAP: inside vendor/, must be skipped. If scanned, it adds many HIGH violations.
module example.com/trap

go 1.22

require golang.org/x/net v0.7.0
