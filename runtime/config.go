package upf

import (
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func ParseConf(file string) error {
	path, err := filepath.Abs(file)
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, &Upf)
	if err != nil {
		return err
	}
	Upf.KernelRouting = false
	return nil
}

type UpfConfig struct {
	CoreAddress        string `yaml:"coreAddress"`
	CoreGtpInterface   string `yaml:"coreGtpInterface"`
	CoreAction         string `yaml:"coreAction"`
	AccessAddress      string `yaml:"accessAddress"`
	AccessGtpInterface string `yaml:"accessGtpInterface"`
	AccessAction       string `yaml:"accessAction"`
	KernelRouting      bool
}
