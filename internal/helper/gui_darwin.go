package helper

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

func apple(ctx context.Context, script string) (string, error) {
	c := exec.CommandContext(ctx, "/usr/bin/osascript", "-")
	c.Stdin = strings.NewReader(script)
	out, e := c.Output()
	if e != nil {
		return "", errors.New("macOS automation failed; check Accessibility permissions")
	}
	return strings.TrimSpace(string(out)), nil
}
func Foreground(ctx context.Context) (string, error) {
	return apple(ctx, `tell application "System Events"
set p to first application process whose frontmost is true
set pid to unix id of p
set appName to name of p
set windowName to ""
try
set windowName to name of front window of p
end try
return (pid as text) & "|" & appName & "|" & windowName
end tell`)
}
func Type(ctx context.Context, target, value string) error {
	current, e := Foreground(ctx)
	if e != nil {
		return e
	}
	if current != target {
		return errors.New("foreground window changed; request approval again")
	}
	escaped := strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`)
	// Script is sent on stdin: the value never appears in process arguments.
	_, e = apple(ctx, `tell application "System Events" to keystroke "`+escaped+`"`)
	return e
}
func Clipboard(ctx context.Context, value string) error {
	c := exec.CommandContext(ctx, "/usr/bin/pbcopy")
	c.Stdin = strings.NewReader(value)
	if c.Run() != nil {
		return errors.New("clipboard unavailable")
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	current, e := exec.Command("/usr/bin/pbpaste").Output()
	if e == nil && bytes.Equal(current, []byte(value)) {
		clear(current)
		if e = exec.Command("/usr/bin/pbcopy").Run(); e != nil {
			return errors.New("clipboard cleanup failed")
		}
	}
	return nil
}
