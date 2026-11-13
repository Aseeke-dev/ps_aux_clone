package main

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const clkTck = 100.0 // Standard Linux USER_HZ (100 ticks per second)

// Process represents a complete row in ps aux
type Process struct {
	User    string
	PID     int
	CPU     float64
	Mem     float64
	VSZ     uint64 // Virtual memory size in KB
	RSS     uint64 // Resident Set Size in KB
	TTY     string
	Stat    string
	Start   string
	Time    string
	Command string
}

func main() {
	totalMemKB := getTotalMemoryKB()
	uptimeSec := getSystemUptime()
	bootTime := time.Now().Add(-time.Duration(uptimeSec * float64(time.Second)))

	entries, err := os.ReadDir("/proc")
	if err != nil {
		fmt.Printf("Error reading /proc: %v\n", err)
		return
	}

	var processes []Process

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		proc, err := readProcessInfo(pid, totalMemKB, uptimeSec, bootTime)
		if err != nil {
			continue
		}

		processes = append(processes, proc)
	}

	// Sort numerically by PID
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].PID < processes[j].PID
	})

	// Print header matching ps aux
	fmt.Printf("%-10s %6s %4s %4s %8s %7s %-8s %-6s %-6s %6s %s\n",
		"USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND")

	for _, p := range processes {
		fmt.Printf("%-10s %6d %4.1f %4.1f %8d %7d %-8s %-6s %-6s %6s %s\n",
			p.User, p.PID, p.CPU, p.Mem, p.VSZ, p.RSS, p.TTY, p.Stat, p.Start, p.Time, p.Command)
	}
}

func readProcessInfo(pid int, totalMemKB uint64, uptimeSec float64, bootTime time.Time) (Process, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))

	// 1. Resolve USER
	info, err := os.Stat(procDir)
	if err != nil {
		return Process{}, err
	}
	username := "unknown"
	if statT, ok := info.Sys().(*syscall.Stat_t); ok {
		uidStr := strconv.FormatUint(uint64(statT.Uid), 10)
		if u, err := user.LookupId(uidStr); err == nil {
			username = u.Username
			if len(username) > 8 {
				username = username[:7] + "+"
			}
		} else {
			username = uidStr
		}
	}

	// 2. Parse /proc/<PID>/stat
	statBytes, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return Process{}, err
	}
	statStr := string(statBytes)

	rightParen := strings.LastIndex(statStr, ")")
	if rightParen == -1 || rightParen+2 >= len(statStr) {
		return Process{}, fmt.Errorf("invalid stat format")
	}

	// Fields after ") ":
	// 0: state, 1: ppid, 2: pgrp, 3: session, 4: tty_nr, 5: tpgid
	// 11: utime, 12: stime, 16: nice, 17: num_threads, 19: starttime, 20: vsize, 21: rss
	fields := strings.Fields(statStr[rightParen+2:])
	if len(fields) < 22 {
		return Process{}, fmt.Errorf("missing stat fields")
	}

	baseState := fields[0]
	pgrp, _ := strconv.Atoi(fields[2])
	session, _ := strconv.Atoi(fields[3])
	ttyNr, _ := strconv.ParseUint(fields[4], 10, 64)
	tpgid, _ := strconv.Atoi(fields[5])

	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	nice, _ := strconv.Atoi(fields[16])
	numThreads, _ := strconv.Atoi(fields[17])
	startTimeTicks, _ := strconv.ParseFloat(fields[19], 64)

	vsizeBytes, _ := strconv.ParseUint(fields[20], 10, 64)
	rssPages, _ := strconv.ParseUint(fields[21], 10, 64)

	// 3. Build detailed STAT string (e.g., Ss, Ssl, S+)
	fullStat := buildStatFlags(baseState, pid, session, pgrp, tpgid, nice, numThreads)

	// 4. Memory calculations (VSZ, RSS, %MEM)
	vszKB := vsizeBytes / 1024
	pageSizeKB := uint64(os.Getpagesize() / 1024)
	rssKB := rssPages * pageSizeKB
	memPercent := 0.0
	if totalMemKB > 0 {
		memPercent = (float64(rssKB) / float64(totalMemKB)) * 100.0
	}

	// 5. CPU & Time calculations (%CPU, START, TIME)
	totalCPUSec := (utime + stime) / clkTck
	startTimeSec := startTimeTicks / clkTck
	elapsedSec := uptimeSec - startTimeSec

	cpuPercent := 0.0
	if elapsedSec > 0 {
		cpuPercent = (totalCPUSec / elapsedSec) * 100.0
	}

	procStartTime := bootTime.Add(time.Duration(startTimeSec * float64(time.Second)))
	startFormatted := formatStartTime(procStartTime)
	timeFormatted := formatCPUTime(totalCPUSec)

	return Process{
		User:    username,
		PID:     pid,
		CPU:     cpuPercent,
		Mem:     memPercent,
		VSZ:     vszKB,
		RSS:     rssKB,
		TTY:     decodeTTY(ttyNr),
		Stat:    fullStat,
		Start:   startFormatted,
		Time:    timeFormatted,
		Command: readCommand(procDir, statStr),
	}, nil
}

func buildStatFlags(state string, pid, session, pgrp, tpgid, nice, numThreads int) string {
	var b strings.Builder
	b.WriteString(state)

	if nice < 0 {
		b.WriteByte('<') // High priority (not nice)
	} else if nice > 0 {
		b.WriteByte('N') // Low priority (nice)
	}

	if pid == session {
		b.WriteByte('s') // Session leader
	}

	if numThreads > 1 {
		b.WriteByte('l') // Multi-threaded
	}

	if tpgid != -1 && pgrp == tpgid {
		b.WriteByte('+') // Foreground process group
	}

	return b.String()
}

func getTotalMemoryKB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				return val
			}
		}
	}
	return 0
}

func getSystemUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		val, _ := strconv.ParseFloat(fields[0], 64)
		return val
	}
	return 0
}

func formatStartTime(t time.Time) string {
	now := time.Now()
	if t.Year() == now.Year() && t.YearDay() == now.YearDay() {
		return t.Format("15:04")
	}
	return t.Format("Jan02")
}

func formatCPUTime(totalSec float64) string {
	mins := int(totalSec) / 60
	secs := int(totalSec) % 60
	return fmt.Sprintf("%d:%02d", mins, secs)
}

func decodeTTY(ttyNr uint64) string {
	if ttyNr == 0 {
		return "?"
	}
	major := (ttyNr >> 8) & 0xff
	minor := (ttyNr & 0xff) | ((ttyNr >> 12) & 0xfff00)

	switch major {
	case 4:
		return fmt.Sprintf("tty%d", minor)
	case 136, 137, 138, 139, 140, 141, 142, 143:
		return fmt.Sprintf("pts/%d", minor)
	default:
		return "?"
	}
}

func readCommand(procDir, statStr string) string {
	cmdlineBytes, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err == nil && len(cmdlineBytes) > 0 {
		cleaned := bytes.ReplaceAll(cmdlineBytes, []byte{0}, []byte{' '})
		cmd := strings.TrimSpace(string(cleaned))
		if cmd != "" {
			return cmd
		}
	}

	leftParen := strings.Index(statStr, "(")
	rightParen := strings.LastIndex(statStr, ")")
	if leftParen != -1 && rightParen > leftParen {
		return "[" + statStr[leftParen+1:rightParen] + "]"
	}

	return "?"
}
