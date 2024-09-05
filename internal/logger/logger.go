// Copyright 2024 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package logger

import (
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
)

type logFormatter struct {
	logrus.TextFormatter
}

// Customized log formatter
func newLogFormatter() *logFormatter {
	return &logFormatter{
		TextFormatter: logrus.TextFormatter{
			ForceColors:            true,
			FullTimestamp:          true,
			DisableTimestamp:       false,
			DisableLevelTruncation: true,
			PadLevelText:           true,
			SortingFunc: func(keys []string) {
				sort.Slice(keys, func(i, j int) bool {
					// returns true if i is before j
					// error always at the end
					if keys[j] == "error" {
						return true
					}
					if keys[i] == "error" {
						return false
					}
					// app always at the begin
					if keys[j] == "app" {
						return false
					}
					if keys[i] == "app" {
						return true
					}
					return strings.Compare(keys[i], keys[j]) == -1
				})
			},
		},
	}
}

func Init(prefix string) {
	logrus.SetFormatter(newLogFormatter())
	logrus.AddHook(newHook(prefix))
}
