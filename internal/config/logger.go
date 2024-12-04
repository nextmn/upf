// Copyright 2024 Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package config

import "github.com/sirupsen/logrus"

type Logger struct {
	Level logrus.Level `yaml:"level"`
}
