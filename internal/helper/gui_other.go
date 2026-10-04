//go:build !darwin

package helper

import (
	"context"
	"errors"
)

func Foreground(context.Context) (string, error) {
	return "", errors.New("type is currently supported only on macOS")
}
func Type(context.Context, string, string) error {
	return errors.New("type is currently supported only on macOS")
}
func Clipboard(context.Context, string) error {
	return errors.New("clipboard is currently supported only on macOS")
}
