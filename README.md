# NextMN-UPF
NextMN-UPF is an experimental 5G UPF implementation. This UPF is implemented in User Space, meaning it does not depend on Linux GTP module.
> [!WARNING]
> This UPF is still at the early stages of development and contains bugs and will crash in unexpected manners.
> Please do not use it for anything other than experimentation. Expect breaking changes until v1.0.0

The following features are implemented:
- IPv4/IPv6 both in inner and outer PDUs (note: IPv6 is not implemented in Linux GTP module)
- PFCP Association Setup Procedure
- PFCP Session Establishment Procedure
- PFCP Session Modification Procedure
- PDRs/FARs, SDF Filters
- Interoperability with Free5GC (you can replace Free5GC's UPF container with NextMN-UPF container) (tested only with IPv4)
- Interoperability with UERANSIM (since 2022-06-24's version in UERANSIM master branch)
- Periodic display of the currently applied PFCP rules

Missing features:
- PFCP Session Deletion Procedure
- PDRs/FARs deletion
- BARs, MARs, URRs, QERs are not handled yet
- Gracefull shutdown procedure
- Any other advanced PFCP use

Other missing things because we are at early stages of development:
- Unit/Integration Tests (Not implemented) + CI/CD
- Testing full IPv6 deployment with UERANSIM+Free5GC integration
- Documentation (WIP)
- Performances (Not the current goal as long as it is decent)
- Storing Sessions/Rules in a database to be more efficient (currently everything is stored in RAM), and the Session/Rules research is not optimal


## Getting started
### Build dependencies
- golang
- make (optional)

### Runtime dependencies
- iproute2
- iptables

### Build and install
Simply run `make build` and `make install`.

### Docker
If you plan using NextMN-UPF with Docker:
- The container required the `NET_ADMIN` capability;
- The container required the forwarding to be enabled (not enabled by the UPF itself);
- The tun interface (`/dev/net/tun`) must be available in the container.

This can be done in `docker-compose.yaml` by defining the following for the service:

```yaml
cap_add:
    - NET_ADMIN
devices:
    - "/dev/net/tun"
sysctls:
    - net.ipv4.ip_forward=1
```

## Author
Louis Royer

## License
MIT
