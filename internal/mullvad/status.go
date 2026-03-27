package mullvad

import (
	"context"
	"fmt"
	"os"
	"time"
)

func CheckLocalMullvad(ctx context.Context, timeout time.Duration) (bool, error) {
	p := New()

	statusCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	isMullvad, err := p.CheckMullvadStatus(statusCtx)
	if err != nil {
		return false, fmt.Errorf("failed to check Mullvad status: %w", err)
	}

	if isMullvad {
		fmt.Println("You are on Mullvad VPN")
		os.Exit(0)
	}

	fmt.Println("You are NOT on Mullvad VPN")
	os.Exit(0)

	return isMullvad, nil
}
