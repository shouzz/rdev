package main

import (
	"context"
	"errors"
	"os"
	"sync"

	"rdev/internal/client"
	"rdev/internal/updater"
)

const intentionalStopExitCode = 75

func deviceActionHandler(cfg updater.Config, identityPath string, allowUninstall bool, cancelUpdates func()) client.DeviceActionHandler {
	var once sync.Once
	return func(ctx context.Context, action string, deleteIdentity bool) (client.DeviceActionOutcome, error) {
		switch action {
		case "upgrade":
			if deleteIdentity {
				return client.DeviceActionOutcome{}, errors.New("invalid upgrade options")
			}
			updated, err := updater.CheckAndApply(ctx, cfg)
			if err != nil {
				return client.DeviceActionOutcome{}, err
			}
			if !updated {
				return client.DeviceActionOutcome{State: "up_to_date"}, nil
			}
			return client.DeviceActionOutcome{State: "applied_restart_pending", After: updater.Restart}, nil
		case "stop", "uninstall":
			if deleteIdentity && action != "uninstall" {
				return client.DeviceActionOutcome{}, errors.New("invalid stop options")
			}
			stop, err := prepareDeviceStop()
			if err != nil {
				return client.DeviceActionOutcome{}, err
			}
			state := "stopping"
			if action == "uninstall" && !allowUninstall {
				return client.DeviceActionOutcome{}, errors.New("remote uninstall is disabled")
			}
			once.Do(cancelUpdates)
			if err := updater.WaitForIdle(); err != nil {
				return client.DeviceActionOutcome{}, err
			}
			if action == "uninstall" {
				if err := uninstallDevice(ctx, identityPath, deleteIdentity); err != nil {
					return client.DeviceActionOutcome{}, err
				}
				state = "uninstalled_stopping"
			}
			return client.DeviceActionOutcome{State: state, After: func() error {
				if err := stop(); err != nil {
					return err
				}
				os.Exit(intentionalStopExitCode)
				return nil
			}}, nil
		default:
			return client.DeviceActionOutcome{}, errors.New("unsupported action")
		}
	}
}
