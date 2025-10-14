# Examples

## Create a volume
```bash
osc-cli fcu CreateVolume --AvailabilityZone eu-west-2a --Size 10
```

## Create DHCP options
```bash
osc-cli api CreateDhcpOptions --DomainName="toot.toot" --DomainNameServers="['1.1.1.1']" --NtpServers="['1.1.1.1']"
```
