package snclient

import (
	"context"
	"fmt"
	"strings"
)

// get open tcp connections from netstat.exe
func (l *CheckConnections) addIPV4(ctx context.Context, check *CheckData) error {
	counter, err := l.getNetstat(ctx, "TCP")
	if err != nil {
		return err
	}
	l.addEntry("ipv4", check, counter)

	return nil
}

func (l *CheckConnections) addIPV6(ctx context.Context, check *CheckData) error {
	counter, err := l.getNetstat(ctx, "TCPv6")
	if err != nil {
		return err
	}
	l.addEntry("ipv6", check, counter)

	return nil
}

func (l *CheckConnections) addEntry(name string, check *CheckData, counter []int64) {
	entry := l.defaultEntry(name)
	for i := range counter {
		s := tcpStates(i)
		entry[s.String()] = fmt.Sprintf("%d", counter[i])
	}

	check.listData = append(check.listData, entry)
}

func (l *CheckConnections) getNetstat(ctx context.Context, name string) ([]int64, error) {
	output, stderr, rc, _, err := l.snc.runExternalCommandString(ctx, "netstat.exe /a /n /p "+name, DefaultCmdTimeout)
	if err != nil {
		return nil, fmt.Errorf("netstat.exe failed: %s\n%s", err.Error(), stderr)
	}
	if rc != 0 {
		return nil, fmt.Errorf("netstat.exe failed: %s\n%s", output, stderr)
	}

	counter := make([]int64, tcpStateMAX-1)

	for _, line := range strings.Split(output, "\n") {
		cols := strings.Fields(line)
		if len(cols) < 4 {
			continue
		}
		if cols[0] != "TCP" {
			continue
		}

		// available states: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat#remarks
		switch cols[3] {
		case "CLOSE_WAIT":
			counter[tcpCloseWait]++
		case "CLOSED":
			counter[tcpClose]++
		case "ESTABLISHED":
			counter[tcpEstablished]++
		case "FIN_WAIT_1":
			counter[tcpFinWait1]++
		case "FIN_WAIT_2":
			counter[tcpFinWait2]++
		case "LAST_ACK":
			counter[tcpLastAck]++
		case "LISTEN", "LISTENING":
			counter[tcpListen]++
		case "SYN_RECEIVED":
			counter[tcpSynRecv]++
		case "SYN_SEND":
			counter[tcpSynSent]++
		case "TIMED_WAIT", "TIME_WAIT":
			counter[tcpTimeWait]++
		default:
			log.Errorf("unhandled tcp state: %s", cols[3])
		}
		counter[tcpTotal]++
	}

	return counter, nil
}
