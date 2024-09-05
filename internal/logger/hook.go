// Copyright 2024 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package logger

import "github.com/sirupsen/logrus"

type loggerHook struct {
	appName string
}

func (h *loggerHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
func (h *loggerHook) Fire(e *logrus.Entry) error {
	e.Data["app"] = h.appName
	return nil
}

func newHook(appName string) *loggerHook {
	return &loggerHook{appName: appName}
}
