// Copyright 2024 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package app

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		errLog := fmt.Sprintf("Error running %s: %s", cmd.Args[0], err)
		log.Println(errLog)
		return err
	}
	return nil
}

func runIPTables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		errLog := fmt.Sprintf("Error running %s: %s", cmd.Args[0], err)
		log.Println(errLog)
		return err
	}
	return nil
}

func runIP6Tables(args ...string) error {
	cmd := exec.Command("ip6tables", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		errLog := fmt.Sprintf("Error running %s: %s", cmd.Args[0], err)
		log.Println(errLog)
		return err
	}
	return nil
}
