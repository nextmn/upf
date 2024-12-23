// Copyright 2022 Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package config

import (
	"io/ioutil"
	"net/netip"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

func ParseConf(file string) (*UpfConfig, error) {
	var conf UpfConfig
	path, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}

type UpfConfig struct {
	Pfcp    PFCP    `yaml:"pfcp"`
	Gtpu    GTPU    `yaml:"gtpu"`
	DNNList []DNN   `yaml:"dnnList"`
	Logger  *Logger `yaml:"logger,omitempty"`
}

type PFCP struct {
	Addr           netip.Addr     `yaml:"addr"`
	NodeID         string         `yaml:"nodeID"`
	RetransTimeout *time.Duration `yaml:"retransTimeout,omitempty"`
	MaxRetrans     *int           `yaml:"maxRetrans,omitempty"`
}

type GTPU struct {
	Forwarder            string               `yaml:"forwarder"`
	TunInterfaceName     *string              `yaml:"tunInterfaceName,omitempty"`
	GTPUProtocolEntities []GTPUProtocolEntity `yaml:"ifList"`
}
type GTPUProtocolEntity struct {
	Addr netip.Addr `yaml:"addr"`
	Type string     `yaml:"type"` // unused for now, should contain N3, N9, etc.
}

type DNN struct {
	Dnn  string `yaml:"dnn"`
	Cidr string `yaml:"cidr"`
}
