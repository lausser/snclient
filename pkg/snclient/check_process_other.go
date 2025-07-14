//go:build !windows

package snclient

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

func (l *CheckProcess) fetchProcs(ctx context.Context, check *CheckData) error {
	procs, err := l.getProcs(ctx)
	if err != nil {
		return fmt.Errorf("fetching processes failed: %s", err.Error())
	}

	userNameLookup := map[uint32]string{}

	for _, proc := range procs {
		l.addProc(ctx, proc, check, userNameLookup)
	}

	return nil
}

func (l *CheckProcess) getProcs(ctx context.Context) ([]*process.Process, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %s", err.Error())
	}

	if len(l.processes) == 0 || slices.Contains(l.processes, "*") {
		return procs, nil
	}

	// filter by process name
	filtered := make([]*process.Process, 0)
	for _, proc := range procs {
		exe := ""
		filename, err := proc.ExeWithContext(ctx)
		if err == nil {
			filename = strings.TrimSuffix(filename, " (deleted)")
			exe = filepath.Base(filename)
		} else {
			cmd, err2 := proc.CmdlineSliceWithContext(ctx)
			if err2 == nil && len(cmd) >= 1 {
				exe = filepath.Base(cmd[0])
			}
		}
		if exe == "" {
			name, err2 := proc.NameWithContext(ctx)
			if err2 == nil {
				exe = fmt.Sprintf("[%s]", name)
			}
		}
		if slices.Contains(l.processes, strings.ToLower(exe)) {
			filtered = append(filtered, proc)
		}
	}

	return filtered, nil
}

func (l *CheckProcess) addProc(ctx context.Context, proc *process.Process, check *CheckData, userNameLookup map[uint32]string) {
	cmdLine, err := proc.CmdlineWithContext(ctx)
	if err != nil {
		log.Debugf("check_process: cmd line error: %s", err.Error())
	}

	exe := ""
	filename, err := proc.ExeWithContext(ctx)
	if err == nil {
		// in case the binary has been removed / updated meanwhile it shows up as "".../path/bin (deleted)""
		// %> ls -la /proc/857375/exe
		// lrwxrwxrwx 1 user group 0 Oct 11 20:40 /proc/857375/exe -> '/usr/bin/ssh (deleted)'
		filename = strings.TrimSuffix(filename, " (deleted)")
		exe = filepath.Base(filename)
	} else {
		cmd, err2 := proc.CmdlineSliceWithContext(ctx)
		if err2 == nil && len(cmd) >= 1 {
			filename = cmd[0]
			exe = filepath.Base(filename)
		}
	}
	if exe == "" {
		name, err2 := proc.NameWithContext(ctx)
		if err2 != nil {
			log.Debugf("check_process: name error: %s", err2.Error())
		} else {
			exe = fmt.Sprintf("[%s]", name)
		}
	}

	states, err := proc.StatusWithContext(ctx)
	if err != nil {
		log.Debugf("check_process: status error: %s", err.Error())
	}
	state := []string{}
	for _, s := range states {
		state = append(state, convertStatusChar(s))
	}

	ctimeMilli, err := proc.CreateTimeWithContext(ctx)
	if err != nil {
		log.Debugf("check_process: CreateTime error: %s", err.Error())
	}

	// skip very young ( < 3000ms ) check_nsc_web processes, they might be checking us and screwing process counts
	if strings.Contains(cmdLine, "check_nsc_web") && time.Now().UnixMilli()-ctimeMilli < 3000 {
		return
	}

	username := ""
	uid := -1
	uids, err := proc.UidsWithContext(ctx)
	if err != nil {
		log.Debugf("check_process: uids error: %s", err.Error())
	} else if len(uids) > 0 {
		// cache user name lookups
		uid = int(uids[0])
		username = userNameLookup[uids[0]]
		if username == "" {
			username, err = proc.UsernameWithContext(ctx)
			if err != nil {
				log.Debugf("check_process: Username error uid %#v: %s", uids, err.Error())
			}
			userNameLookup[uids[0]] = username
		}
	}

	// process does not exist anymore
	if exe == "" && uid == -1 {
		if ok, _ := process.PidExistsWithContext(ctx, proc.Pid); !ok {
			return
		}
	}

	mem, err := proc.MemoryInfoWithContext(ctx)
	if err != nil {
		log.Debugf("check_process: meminfo error: %s", err.Error())
		mem = &process.MemoryInfoStat{}
	}

	cpu, err := proc.CPUPercentWithContext(ctx)
	if err != nil {
		log.Debugf("check_process: cpuinfo error: %s", err.Error())
	}

	check.listData = append(check.listData, map[string]string{
		"process":      exe,
		"state":        strings.Join(state, ","),
		"command_line": cmdLine,
		"creation":     fmt.Sprintf("%d", ctimeMilli/1000),
		"exe":          exe,
		"filename":     filename,
		"pid":          fmt.Sprintf("%d", proc.Pid),
		"uid":          fmt.Sprintf("%d", uid),
		"username":     username,
		"virtual":      fmt.Sprintf("%d", mem.VMS),
		"rss":          fmt.Sprintf("%d", mem.RSS),
		"pagefile":     fmt.Sprintf("%d", mem.Swap),
		"cpu":          fmt.Sprintf("%f", cpu),
	})
}

func convertStatusChar(letter string) string {
	switch strings.ToLower(letter) {
	case "i", "idle":
		return "idle"
	case "l", "lock":
		return "lock"
	case "r", "running":
		return "running"
	case "s", "sleep":
		return "sleep"
	case "t", "stop":
		return "stop"
	case "w", "wait":
		return "wait"
	case "z", "zombie":
		return "zombie"
	case "b", "blocked":
		return "blocked"
	default:
		return "unknown"
	}
}
