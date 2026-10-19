// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/logging"
)

// newDeliveryPluginManager builds the process's one delivery plugin manager
// (W20-20). KRYPTKEEPER_DELIVERY_PLUGINS=off or no database leaves plugins
// off: the API then answers 503 and plugin targets fail with a plain reason.
//
// A KRYPTKEEPER_PLUGIN_TRUSTED_KEYS file that cannot be read or parsed stops
// startup: running on with fewer trusted keys than configured would refuse
// installs the operator expects to work, and say nothing about why. The
// kill switch skips that check: a hub with plugins off must start even
// when the plugin config is what broke.
func newDeliveryPluginManager(coreDB *sql.DB, isPostgres bool) *bootstrap.DeliveryPluginManager {
	var trust *bootstrap.PluginTrust
	if bootstrap.DeliveryPluginsEnabledFromEnv() {
		var err error
		if trust, err = bootstrap.PluginTrustFromEnv(); err != nil {
			logging.Fatalf("delivery plugins: %v", err)
		}
	}
	mgr := bootstrap.NewDeliveryPluginManager(coreDB, isPostgres, bootstrap.NewPendingActionStoreFromEnv(), trust)
	switch {
	case mgr != nil:
		fp, verified := trust.Counts()
		logging.Infof("delivery plugins: on (/api/v1/delivery-plugins; High/Critical capabilities need a second approver; signing keys: %d first-party, %d trusted)", fp, verified)
	case !bootstrap.DeliveryPluginsEnabledFromEnv():
		logging.Info("delivery plugins: off (KRYPTKEEPER_DELIVERY_PLUGINS=off)")
	default:
		logging.Info("delivery plugins: off (no hub database)")
	}
	return mgr
}

// deliveryPluginOption hands the manager, and its approval executor, to
// the server.
func deliveryPluginOption(mgr *bootstrap.DeliveryPluginManager) bootstrap.ServerOption {
	if mgr == nil {
		return nil
	}
	return func(c *bootstrap.ServerConfig) {
		bootstrap.WithDeliveryPlugins(mgr)(c)
		bootstrap.WithActionExecutor(bootstrap.ActionEnableDeliveryPlugin, mgr.ExecuteEnable)(c)
	}
}
