//go:build windows

package main

import (
	"os"
	"testing"

	"golang.org/x/sys/windows/svc"
)

func TestIntentionalStopDoesNotReportServiceFailure(t *testing.T) {
	if os.Getenv("RDEV_WRAPPER_STOP_CHILD") == "1" {
		os.Exit(75)
	}
	t.Setenv("RDEV_WRAPPER_STOP_CHILD", "1")
	service := &wrapperService{cfg: wrapperConfig{
		Command: []string{os.Args[0], "-test.run=^TestIntentionalStopDoesNotReportServiceFailure$"},
	}}
	status := make(chan svc.Status, 5)
	specific, code := service.Execute(nil, make(chan svc.ChangeRequest), status)
	if specific || code != 0 {
		t.Fatalf("intentional stop reported service failure: %v %d", specific, code)
	}
	close(status)
	var last svc.Status
	for last = range status {
	}
	if last.State != svc.Stopped {
		t.Fatal("wrapper did not report stopped")
	}
}
