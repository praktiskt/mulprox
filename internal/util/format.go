package util

import "fmt"

func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n >= unit*unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func FormatBytesUint(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for n := n / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func FormatLatency(ms float64) string {
	if ms < 1 {
		return "—"
	}
	return fmt.Sprintf("%.0fms", ms)
}

func LatencyClass(ms float64) string {
	if ms < 0 {
		return ""
	}
	if ms < 100 {
		return "latency-good"
	}
	if ms < 300 {
		return "latency-ok"
	}
	return "latency-bad"
}
