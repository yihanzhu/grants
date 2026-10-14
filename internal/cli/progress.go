package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// progress shows one updating line on a terminal while a slow scan runs. It stays
// silent for the first second, so quick runs print nothing extra.
type progress struct {
	w     io.Writer
	width int
	delay time.Duration

	mu     sync.Mutex
	stages map[string][2]int // stage -> done, total, for stages still running
	start  time.Time
	shown  bool

	stop chan struct{}
	done chan struct{}
}

func startProgress(w io.Writer, width int) *progress {
	p := &progress{
		w: w, width: width, delay: time.Second,
		stages: map[string][2]int{}, start: time.Now(),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go p.loop()
	return p
}

// update is the callback for scan.Options.Progress. Workers call it concurrently.
func (p *progress) update(stage string, done, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if done >= total {
		delete(p.stages, stage)
		return
	}
	p.stages[stage] = [2]int{done, total}
}

func (p *progress) loop() {
	defer close(p.done)
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.draw()
		}
	}
}

func (p *progress) draw() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.start) < p.delay || len(p.stages) == 0 {
		return
	}
	line := progressLine(p.stages)
	if p.width > 1 {
		line = truncEnd(line, p.width-1)
	}
	fmt.Fprintf(p.w, "\r\x1b[2K%s", line)
	p.shown = true
}

// finish stops the updates and clears the line.
func (p *progress) finish() {
	close(p.stop)
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.shown {
		fmt.Fprint(p.w, "\r\x1b[2K")
	}
}

// progressLine words the running stages, such as
// "Reading Codex sessions 1,200/4,823 · Claude Code transcripts 40/900".
func progressLine(stages map[string][2]int) string {
	names := make([]string, 0, len(stages))
	for n := range stages {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s %s/%s", n, commas(stages[n][0]), commas(stages[n][1]))
	}
	return "Reading " + strings.Join(parts, " · ")
}
