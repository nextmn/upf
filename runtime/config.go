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

type PDR struct {
	TEID  uint32 `yaml:"teid"`
	FARID uint32 `yaml:"farid"`
}

type FAR struct {
	ID       uint32 `yaml:"id"`
	TEID     uint32 `yaml:"teid"`
	GTPUPeer string `yaml:"gtpuPeer"`
}

type GTPUProtocolEntity struct {
	IpAddress string `yaml:"ipAddress"`
	PDRs      []*PDR `yaml:"pdrs"`
	FARs      []*FAR `yaml:"fars"`
}

type IPEndpoint struct {
	GTPUPeer  string `yaml:"gtpuPeer"`
	TEID      uint32 `yaml:"teid"`
	LocalAddr string `yaml:"laddr"`
}

type UpfConfig struct {
	GTPUProtocolEntities []*GTPUProtocolEntity `yaml:"entities"`
	IPEndpoints          []*IPEndpoint         `yaml:"ipEndpoints"`
}
