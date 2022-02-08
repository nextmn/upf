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
	return nil
}

type DNN struct {
	Dnn  string `yaml:"dnn"`
	Cidr string `yaml:"cidr"`
}

type RAN struct {
	IPv4Address string `yaml:"ipv4"`
	IPv6Address string `yaml:"ipv6"`
}

type UpfConfig struct {
	PFCPAddress          *string  `yaml:"pfcp-address,omitempty"`
	GTPUProtocolEntities []string `yaml:"gtpu-entities"`
	DNNList              []*DNN   `yaml:"dnn_list,omitempty"`
	SimulateRAN          *RAN     `yaml:"simulate-ran,omitempty"`
}
