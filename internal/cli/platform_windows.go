package cli

import (
	"errors"
)

func disableCoreDumps() error { return nil }
func protectedPath(string) error {
	return errors.New("Windows production service ACL validation is not implemented; use --dev for evaluation")
}
