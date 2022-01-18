package upf

import (
	"io/ioutil"
	"path/filepath"

	"github.com/wmnsk/go-gtp/gtpv1"
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

type FTEID struct {
	TEID      uint32 `yaml:"teid"`
	IPAddress string `yaml:"ipAddress"`
}

type SDFFilter struct {
	FlowDescription string `yaml:"description"`
}

type UEIPAddress struct {
	IPAddress string `yaml:"ip-address"`
}

type PDI struct {
	SourceInterface string       `yaml:"sourceInterface"`
	FTEID           *FTEID       `yaml:"fteid,omitempty"` // not required if source is not encapsulated
	SDFFilter       *SDFFilter   `yaml:"sdf-filter,omitempty"`
	UEIPAddress     *UEIPAddress `yaml:"ue-ip-address,omitempty"`
}

type PDR struct {
	ID                 uint32              `yaml:"id"`
	PDI                *PDI                `yaml:"pdi"`
	Precedence         uint32              `yaml:"precedence"`
	FARID              uint32              `yaml:"farid"`
	OuterHeaderRemoval *OuterHeaderRemoval `yaml:"outerHeaderRemoval,omitempty"`
}

type OuterHeaderRemoval struct {
	description             uint32
	extensionHeaderDeletion uint32
}

type PDRs []*PDR

func (pdrs PDRs) Len() int {
	return len(pdrs)
}
func (pdrs PDRs) Less(i, j int) bool {
	// element with highest precedence (lowest value in Precedence IE) should be sorted first
	return pdrs[i].Precedence < pdrs[j].Precedence
}

func (pdrs PDRs) Swap(i, j int) {
	pdrs[i], pdrs[j] = pdrs[j], pdrs[i]
}

type OuterHeaderCreation struct {
	TEID     uint32 `yaml:"teid"`
	GTPUPeer string `yaml:"gtpuPeer"`
	uConn    *gtpv1.UPlaneConn
}

type ForwardingParameters struct {
	DestinationInterface string               `yaml:"destinationInterface"`
	OuterHeaderCreation  *OuterHeaderCreation `yaml:"outerHeaderCreation,omitempty"`
}

type FAR struct {
	ID                   uint32                `yaml:"id"`
	ForwardingParameters *ForwardingParameters `yaml:"forwardingParameters"`
}

type PFCPSession struct {
	PDRS []*PDR `yaml:"pdrs"`
	FARS []*FAR `yaml:"fars"`
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
	GTPUProtocolEntities []string       `yaml:"gtpu-entities"`
	DNNList              []*DNN         `yaml:"dnn_list,omitempty"`
	PFCPSessions         []*PFCPSession `yaml:"pfcp-sessions"`
	SimulateRAN          *RAN           `yaml:"simulate-ran,omitempty"`
}
