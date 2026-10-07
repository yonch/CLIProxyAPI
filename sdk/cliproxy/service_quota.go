package cliproxy

import (
	"context"
	"errors"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	quotaUsageRefreshInterval = 5 * time.Minute
	// quotaUsageReadTimeout bounds one background usage read: reads run serially, so one
	// hung read would otherwise stall every later read. Request traffic is unaffected.
	quotaUsageReadTimeout = 30 * time.Second
)

// startQuotaUsageRefresh reads the usage endpoint of every eligible Claude and Codex OAuth
// credential now and then every quotaUsageRefreshInterval until ctx ends. Reset times are
// kept only in memory, so the startup sweep restores the greedy routing observations a
// restart lost, and the periodic sweep tracks quota consumed outside the proxy.
func (s *Service) startQuotaUsageRefresh(ctx context.Context) {
	if s == nil || s.coreManager == nil {
		return
	}
	go s.runQuotaUsageRefresh(ctx, quotaUsageRefreshInterval, quotaUsageReadTimeout)
}

func (s *Service) runQuotaUsageRefresh(ctx context.Context, interval, readTimeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.refreshQuotaUsage(ctx, readTimeout)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// refreshQuotaUsage runs one sweep. Failures are logged and leave known schedules intact.
func (s *Service) refreshQuotaUsage(ctx context.Context, readTimeout time.Duration) {
	for _, auth := range s.coreManager.List() {
		if ctx.Err() != nil {
			return
		}
		errRefresh := s.coreManager.RefreshQuotaResetSchedule(ctx, auth.ID, readTimeout)
		switch {
		case errRefresh == nil, errors.Is(errRefresh, coreauth.ErrQuotaUsageNotEligible):
		case errors.Is(errRefresh, coreauth.ErrQuotaUsageObservationRejected), ctx.Err() != nil:
			log.WithField("auth_id", auth.ID).Debugf("quota usage refresh skipped: %v", errRefresh)
		default:
			log.WithField("auth_id", auth.ID).Warnf("quota usage refresh failed: %v", errRefresh)
		}
	}
}
