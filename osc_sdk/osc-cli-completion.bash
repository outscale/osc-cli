#/usr/bin/env bash
# OUTSCALE API

UpdateVpnConnection()
{
    COMPREPLY=($(compgen -W " --ClientGatewayId --DryRun --VirtualGatewayId --VpnConnectionId --VpnOptions" -- ${cur}))
}
UpdateVolume()
{
    COMPREPLY=($(compgen -W " --DryRun --Iops --Size --VolumeId --VolumeType" -- ${cur}))
}
UpdateVm()
{
    COMPREPLY=($(compgen -W " --BlockDeviceMappings --BsuOptimized --DeletionProtection --DryRun --IsSourceDestChecked --KeypairName --NestedVirtualization --Performance --SecurityGroupIds --UserData --VmId --VmInitiatedShutdownBehavior --VmType" -- ${cur}))
}
UpdateSubnet()
{
    COMPREPLY=($(compgen -W " --DryRun --MapPublicIpOnLaunch --SubnetId" -- ${cur}))
}
UpdateSnapshot()
{
    COMPREPLY=($(compgen -W " --DryRun --PermissionsToCreateVolume --SnapshotId" -- ${cur}))
}
UpdateServerCertificate()
{
    COMPREPLY=($(compgen -W " --DryRun --Name --NewName --NewPath" -- ${cur}))
}
UpdateRoutePropagation()
{
    COMPREPLY=($(compgen -W " --DryRun --Enable --RouteTableId --VirtualGatewayId" -- ${cur}))
}
UpdateRoute()
{
    COMPREPLY=($(compgen -W " --DestinationIpRange --DryRun --GatewayId --NatServiceId --NetPeeringId --NicId --RouteTableId --VmId" -- ${cur}))
}
UpdateNic()
{
    COMPREPLY=($(compgen -W " --Description --DryRun --LinkNic --NicId --SecurityGroupIds" -- ${cur}))
}
UpdateNetAccessPoint()
{
    COMPREPLY=($(compgen -W " --AddRouteTableIds --DryRun --NetAccessPointId --RemoveRouteTableIds" -- ${cur}))
}
UpdateNet()
{
    COMPREPLY=($(compgen -W " --DhcpOptionsSetId --DryRun --NetId" -- ${cur}))
}
UpdateLoadBalancer()
{
    COMPREPLY=($(compgen -W " --AccessLog --DryRun --HealthCheck --LoadBalancerName --LoadBalancerPort --PolicyNames --PublicIp --SecuredCookies --SecurityGroups --ServerCertificateId" -- ${cur}))
}
UpdateListenerRule()
{
    COMPREPLY=($(compgen -W " --DryRun --HostPattern --ListenerRuleName --PathPattern" -- ${cur}))
}
UpdateImage()
{
    COMPREPLY=($(compgen -W " --DryRun --ImageId --PermissionsToLaunch" -- ${cur}))
}
UpdateFlexibleGpu()
{
    COMPREPLY=($(compgen -W " --DeleteOnVmDeletion --DryRun --FlexibleGpuId" -- ${cur}))
}
UpdateDirectLinkInterface()
{
    COMPREPLY=($(compgen -W " --DirectLinkInterfaceId --DryRun --Mtu" -- ${cur}))
}
UpdateCa()
{
    COMPREPLY=($(compgen -W " --CaId --Description --DryRun" -- ${cur}))
}
UpdateApiAccessRule()
{
    COMPREPLY=($(compgen -W " --ApiAccessRuleId --CaIds --Cns --Description --DryRun --IpRanges" -- ${cur}))
}
UpdateApiAccessPolicy()
{
    COMPREPLY=($(compgen -W " --DryRun --MaxAccessKeyExpirationSeconds --RequireTrustedEnv" -- ${cur}))
}
UpdateAccount()
{
    COMPREPLY=($(compgen -W " --AdditionalEmails --City --CompanyName --Country --DryRun --Email --FirstName --JobTitle --LastName --MobileNumber --PhoneNumber --StateProvince --VatNumber --ZipCode" -- ${cur}))
}
UpdateAccessKey()
{
    COMPREPLY=($(compgen -W " --AccessKeyId --DryRun --ExpirationDate --State" -- ${cur}))
}
UnlinkVolume()
{
    COMPREPLY=($(compgen -W " --DryRun --ForceUnlink --VolumeId" -- ${cur}))
}
UnlinkVirtualGateway()
{
    COMPREPLY=($(compgen -W " --DryRun --NetId --VirtualGatewayId" -- ${cur}))
}
UnlinkRouteTable()
{
    COMPREPLY=($(compgen -W " --DryRun --LinkRouteTableId" -- ${cur}))
}
UnlinkPublicIp()
{
    COMPREPLY=($(compgen -W " --DryRun --LinkPublicIpId --PublicIp" -- ${cur}))
}
UnlinkPrivateIps()
{
    COMPREPLY=($(compgen -W " --DryRun --NicId --PrivateIps" -- ${cur}))
}
UnlinkNic()
{
    COMPREPLY=($(compgen -W " --DryRun --LinkNicId" -- ${cur}))
}
UnlinkLoadBalancerBackendMachines()
{
    COMPREPLY=($(compgen -W " --BackendIps --BackendVmIds --DryRun --LoadBalancerName" -- ${cur}))
}
UnlinkInternetService()
{
    COMPREPLY=($(compgen -W " --DryRun --InternetServiceId --NetId" -- ${cur}))
}
UnlinkFlexibleGpu()
{
    COMPREPLY=($(compgen -W " --DryRun --FlexibleGpuId" -- ${cur}))
}
StopVms()
{
    COMPREPLY=($(compgen -W " --DryRun --ForceStop --VmIds" -- ${cur}))
}
StartVms()
{
    COMPREPLY=($(compgen -W " --DryRun --VmIds" -- ${cur}))
}
SendResetPasswordEmail()
{
    COMPREPLY=($(compgen -W " --DryRun --Email" -- ${cur}))
}
ResetAccountPassword()
{
    COMPREPLY=($(compgen -W " --DryRun --Password --Token" -- ${cur}))
}
RejectNetPeering()
{
    COMPREPLY=($(compgen -W " --DryRun --NetPeeringId" -- ${cur}))
}
RegisterVmsInLoadBalancer()
{
    COMPREPLY=($(compgen -W " --BackendVmIds --DryRun --LoadBalancerName" -- ${cur}))
}
RebootVms()
{
    COMPREPLY=($(compgen -W " --DryRun --VmIds" -- ${cur}))
}
ReadVpnConnections()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadVolumes()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadVmsState()
{
    COMPREPLY=($(compgen -W " --AllVms --DryRun --Filters" -- ${cur}))
}
ReadVmsHealth()
{
    COMPREPLY=($(compgen -W " --BackendVmIds --DryRun --LoadBalancerName" -- ${cur}))
}
ReadVms()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadVmTypes()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadVirtualGateways()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadTags()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadSubregions()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadSubnets()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadSnapshots()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadSnapshotExportTasks()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadServerCertificates()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadSecurityGroups()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadSecretAccessKey()
{
    COMPREPLY=($(compgen -W " --AccessKeyId --DryRun" -- ${cur}))
}
ReadRouteTables()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadRegions()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadQuotas()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadPublicIps()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadPublicIpRanges()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadPublicCatalog()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadProductTypes()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadNics()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadNets()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadNetPeerings()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadNetAccessPoints()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadNetAccessPointServices()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadNatServices()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadLocations()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadLoadBalancers()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadLoadBalancerTags()
{
    COMPREPLY=($(compgen -W " --DryRun --LoadBalancerNames" -- ${cur}))
}
ReadListenerRules()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadKeypairs()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadInternetServices()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadImages()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadImageExportTasks()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadFlexibleGpus()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadFlexibleGpuCatalog()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadDirectLinks()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadDirectLinkInterfaces()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadDhcpOptions()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadConsumptionAccount()
{
    COMPREPLY=($(compgen -W " --DryRun --FromDate --Overall --ToDate" -- ${cur}))
}
ReadConsoleOutput()
{
    COMPREPLY=($(compgen -W " --DryRun --VmId" -- ${cur}))
}
ReadClientGateways()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadCatalog()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadCas()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadApiLogs()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters --NextPageToken --ResultsPerPage --With" -- ${cur}))
}
ReadApiAccessRules()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
ReadApiAccessPolicy()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadAdminPassword()
{
    COMPREPLY=($(compgen -W " --DryRun --VmId" -- ${cur}))
}
ReadAccounts()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
ReadAccessKeys()
{
    COMPREPLY=($(compgen -W " --DryRun --Filters" -- ${cur}))
}
LinkVolume()
{
    COMPREPLY=($(compgen -W " --DeviceName --DryRun --VmId --VolumeId" -- ${cur}))
}
LinkVirtualGateway()
{
    COMPREPLY=($(compgen -W " --DryRun --NetId --VirtualGatewayId" -- ${cur}))
}
LinkRouteTable()
{
    COMPREPLY=($(compgen -W " --DryRun --RouteTableId --SubnetId" -- ${cur}))
}
LinkPublicIp()
{
    COMPREPLY=($(compgen -W " --AllowRelink --DryRun --NicId --PrivateIp --PublicIp --PublicIpId --VmId" -- ${cur}))
}
LinkPrivateIps()
{
    COMPREPLY=($(compgen -W " --AllowRelink --DryRun --NicId --PrivateIps --SecondaryPrivateIpCount" -- ${cur}))
}
LinkNic()
{
    COMPREPLY=($(compgen -W " --DeviceNumber --DryRun --NicId --VmId" -- ${cur}))
}
LinkLoadBalancerBackendMachines()
{
    COMPREPLY=($(compgen -W " --BackendIps --BackendVmIds --DryRun --LoadBalancerName" -- ${cur}))
}
LinkInternetService()
{
    COMPREPLY=($(compgen -W " --DryRun --InternetServiceId --NetId" -- ${cur}))
}
LinkFlexibleGpu()
{
    COMPREPLY=($(compgen -W " --DryRun --FlexibleGpuId --VmId" -- ${cur}))
}
DeregisterVmsInLoadBalancer()
{
    COMPREPLY=($(compgen -W " --BackendVmIds --DryRun --LoadBalancerName" -- ${cur}))
}
DeleteVpnConnectionRoute()
{
    COMPREPLY=($(compgen -W " --DestinationIpRange --DryRun --VpnConnectionId" -- ${cur}))
}
DeleteVpnConnection()
{
    COMPREPLY=($(compgen -W " --DryRun --VpnConnectionId" -- ${cur}))
}
DeleteVolume()
{
    COMPREPLY=($(compgen -W " --DryRun --VolumeId" -- ${cur}))
}
DeleteVms()
{
    COMPREPLY=($(compgen -W " --DryRun --VmIds" -- ${cur}))
}
DeleteVirtualGateway()
{
    COMPREPLY=($(compgen -W " --DryRun --VirtualGatewayId" -- ${cur}))
}
DeleteTags()
{
    COMPREPLY=($(compgen -W " --DryRun --ResourceIds --Tags" -- ${cur}))
}
DeleteSubnet()
{
    COMPREPLY=($(compgen -W " --DryRun --SubnetId" -- ${cur}))
}
DeleteSnapshot()
{
    COMPREPLY=($(compgen -W " --DryRun --SnapshotId" -- ${cur}))
}
DeleteServerCertificate()
{
    COMPREPLY=($(compgen -W " --DryRun --Name" -- ${cur}))
}
DeleteSecurityGroupRule()
{
    COMPREPLY=($(compgen -W " --DryRun --Flow --FromPortRange --IpProtocol --IpRange --Rules --SecurityGroupAccountIdToUnlink --SecurityGroupId --SecurityGroupNameToUnlink --ToPortRange" -- ${cur}))
}
DeleteSecurityGroup()
{
    COMPREPLY=($(compgen -W " --DryRun --SecurityGroupId --SecurityGroupName" -- ${cur}))
}
DeleteRouteTable()
{
    COMPREPLY=($(compgen -W " --DryRun --RouteTableId" -- ${cur}))
}
DeleteRoute()
{
    COMPREPLY=($(compgen -W " --DestinationIpRange --DryRun --RouteTableId" -- ${cur}))
}
DeletePublicIp()
{
    COMPREPLY=($(compgen -W " --DryRun --PublicIp --PublicIpId" -- ${cur}))
}
DeleteNic()
{
    COMPREPLY=($(compgen -W " --DryRun --NicId" -- ${cur}))
}
DeleteNetPeering()
{
    COMPREPLY=($(compgen -W " --DryRun --NetPeeringId" -- ${cur}))
}
DeleteNetAccessPoint()
{
    COMPREPLY=($(compgen -W " --DryRun --NetAccessPointId" -- ${cur}))
}
DeleteNet()
{
    COMPREPLY=($(compgen -W " --DryRun --NetId" -- ${cur}))
}
DeleteNatService()
{
    COMPREPLY=($(compgen -W " --DryRun --NatServiceId" -- ${cur}))
}
DeleteLoadBalancerTags()
{
    COMPREPLY=($(compgen -W " --DryRun --LoadBalancerNames --Tags" -- ${cur}))
}
DeleteLoadBalancerPolicy()
{
    COMPREPLY=($(compgen -W " --DryRun --LoadBalancerName --PolicyName" -- ${cur}))
}
DeleteLoadBalancerListeners()
{
    COMPREPLY=($(compgen -W " --DryRun --LoadBalancerName --LoadBalancerPorts" -- ${cur}))
}
DeleteLoadBalancer()
{
    COMPREPLY=($(compgen -W " --DryRun --LoadBalancerName" -- ${cur}))
}
DeleteListenerRule()
{
    COMPREPLY=($(compgen -W " --DryRun --ListenerRuleName" -- ${cur}))
}
DeleteKeypair()
{
    COMPREPLY=($(compgen -W " --DryRun --KeypairName" -- ${cur}))
}
DeleteInternetService()
{
    COMPREPLY=($(compgen -W " --DryRun --InternetServiceId" -- ${cur}))
}
DeleteImage()
{
    COMPREPLY=($(compgen -W " --DryRun --ImageId" -- ${cur}))
}
DeleteFlexibleGpu()
{
    COMPREPLY=($(compgen -W " --DryRun --FlexibleGpuId" -- ${cur}))
}
DeleteExportTask()
{
    COMPREPLY=($(compgen -W " --DryRun --ExportTaskId" -- ${cur}))
}
DeleteDirectLinkInterface()
{
    COMPREPLY=($(compgen -W " --DirectLinkInterfaceId --DryRun" -- ${cur}))
}
DeleteDirectLink()
{
    COMPREPLY=($(compgen -W " --DirectLinkId --DryRun" -- ${cur}))
}
DeleteDhcpOptions()
{
    COMPREPLY=($(compgen -W " --DhcpOptionsSetId --DryRun" -- ${cur}))
}
DeleteClientGateway()
{
    COMPREPLY=($(compgen -W " --ClientGatewayId --DryRun" -- ${cur}))
}
DeleteCa()
{
    COMPREPLY=($(compgen -W " --CaId --DryRun" -- ${cur}))
}
DeleteApiAccessRule()
{
    COMPREPLY=($(compgen -W " --ApiAccessRuleId --DryRun" -- ${cur}))
}
DeleteAccessKey()
{
    COMPREPLY=($(compgen -W " --AccessKeyId --DryRun" -- ${cur}))
}
CreateVpnConnectionRoute()
{
    COMPREPLY=($(compgen -W " --DestinationIpRange --DryRun --VpnConnectionId" -- ${cur}))
}
CreateVpnConnection()
{
    COMPREPLY=($(compgen -W " --ClientGatewayId --ConnectionType --DryRun --StaticRoutesOnly --VirtualGatewayId" -- ${cur}))
}
CreateVolume()
{
    COMPREPLY=($(compgen -W " --DryRun --Iops --Size --SnapshotId --SubregionName --VolumeType" -- ${cur}))
}
CreateVms()
{
    COMPREPLY=($(compgen -W " --BlockDeviceMappings --BootOnCreation --BsuOptimized --ClientToken --DeletionProtection --DryRun --ImageId --KeypairName --MaxVmsCount --MinVmsCount --NestedVirtualization --Nics --Performance --Placement --PrivateIps --SecurityGroupIds --SecurityGroups --SubnetId --UserData --VmInitiatedShutdownBehavior --VmType" -- ${cur}))
}
CreateVirtualGateway()
{
    COMPREPLY=($(compgen -W " --ConnectionType --DryRun" -- ${cur}))
}
CreateTags()
{
    COMPREPLY=($(compgen -W " --DryRun --ResourceIds --Tags" -- ${cur}))
}
CreateSubnet()
{
    COMPREPLY=($(compgen -W " --DryRun --IpRange --NetId --SubregionName" -- ${cur}))
}
CreateSnapshotExportTask()
{
    COMPREPLY=($(compgen -W " --DryRun --OsuExport --SnapshotId" -- ${cur}))
}
CreateSnapshot()
{
    COMPREPLY=($(compgen -W " --Description --DryRun --FileLocation --SnapshotSize --SourceRegionName --SourceSnapshotId --VolumeId" -- ${cur}))
}
CreateServerCertificate()
{
    COMPREPLY=($(compgen -W " --Body --Chain --DryRun --Name --Path --PrivateKey" -- ${cur}))
}
CreateSecurityGroupRule()
{
    COMPREPLY=($(compgen -W " --DryRun --Flow --FromPortRange --IpProtocol --IpRange --Rules --SecurityGroupAccountIdToLink --SecurityGroupId --SecurityGroupNameToLink --ToPortRange" -- ${cur}))
}
CreateSecurityGroup()
{
    COMPREPLY=($(compgen -W " --Description --DryRun --NetId --SecurityGroupName" -- ${cur}))
}
CreateRouteTable()
{
    COMPREPLY=($(compgen -W " --DryRun --NetId" -- ${cur}))
}
CreateRoute()
{
    COMPREPLY=($(compgen -W " --DestinationIpRange --DryRun --GatewayId --NatServiceId --NetPeeringId --NicId --RouteTableId --VmId" -- ${cur}))
}
CreatePublicIp()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
CreateNic()
{
    COMPREPLY=($(compgen -W " --Description --DryRun --PrivateIps --SecurityGroupIds --SubnetId" -- ${cur}))
}
CreateNetPeering()
{
    COMPREPLY=($(compgen -W " --AccepterNetId --DryRun --SourceNetId" -- ${cur}))
}
CreateNetAccessPoint()
{
    COMPREPLY=($(compgen -W " --DryRun --NetId --RouteTableIds --ServiceName" -- ${cur}))
}
CreateNet()
{
    COMPREPLY=($(compgen -W " --DryRun --IpRange --Tenancy" -- ${cur}))
}
CreateNatService()
{
    COMPREPLY=($(compgen -W " --DryRun --PublicIpId --SubnetId" -- ${cur}))
}
CreateLoadBalancerTags()
{
    COMPREPLY=($(compgen -W " --DryRun --LoadBalancerNames --Tags" -- ${cur}))
}
CreateLoadBalancerPolicy()
{
    COMPREPLY=($(compgen -W " --CookieExpirationPeriod --CookieName --DryRun --LoadBalancerName --PolicyName --PolicyType" -- ${cur}))
}
CreateLoadBalancerListeners()
{
    COMPREPLY=($(compgen -W " --DryRun --Listeners --LoadBalancerName" -- ${cur}))
}
CreateLoadBalancer()
{
    COMPREPLY=($(compgen -W " --DryRun --Listeners --LoadBalancerName --LoadBalancerType --PublicIp --SecurityGroups --Subnets --SubregionNames --Tags" -- ${cur}))
}
CreateListenerRule()
{
    COMPREPLY=($(compgen -W " --DryRun --Listener --ListenerRule --VmIds" -- ${cur}))
}
CreateKeypair()
{
    COMPREPLY=($(compgen -W " --DryRun --KeypairName --PublicKey" -- ${cur}))
}
CreateInternetService()
{
    COMPREPLY=($(compgen -W " --DryRun" -- ${cur}))
}
CreateImageExportTask()
{
    COMPREPLY=($(compgen -W " --DryRun --ImageId --OsuExport" -- ${cur}))
}
CreateImage()
{
    COMPREPLY=($(compgen -W " --Architecture --BlockDeviceMappings --Description --DryRun --FileLocation --ImageName --NoReboot --RootDeviceName --SourceImageId --SourceRegionName --VmId" -- ${cur}))
}
CreateFlexibleGpu()
{
    COMPREPLY=($(compgen -W " --DeleteOnVmDeletion --DryRun --Generation --ModelName --SubregionName" -- ${cur}))
}
CreateDirectLinkInterface()
{
    COMPREPLY=($(compgen -W " --DirectLinkId --DirectLinkInterface --DryRun" -- ${cur}))
}
CreateDirectLink()
{
    COMPREPLY=($(compgen -W " --Bandwidth --DirectLinkName --DryRun --Location" -- ${cur}))
}
CreateDhcpOptions()
{
    COMPREPLY=($(compgen -W " --DomainName --DomainNameServers --DryRun --LogServers --NtpServers" -- ${cur}))
}
CreateClientGateway()
{
    COMPREPLY=($(compgen -W " --BgpAsn --ConnectionType --DryRun --PublicIp" -- ${cur}))
}
CreateCa()
{
    COMPREPLY=($(compgen -W " --CaPem --Description --DryRun" -- ${cur}))
}
CreateApiAccessRule()
{
    COMPREPLY=($(compgen -W " --CaIds --Cns --Description --DryRun --IpRanges" -- ${cur}))
}
CreateAccount()
{
    COMPREPLY=($(compgen -W " --AdditionalEmails --City --CompanyName --Country --CustomerId --DryRun --Email --FirstName --JobTitle --LastName --MobileNumber --PhoneNumber --StateProvince --VatNumber --ZipCode" -- ${cur}))
}
CreateAccessKey()
{
    COMPREPLY=($(compgen -W " --DryRun --ExpirationDate" -- ${cur}))
}
CheckAuthentication()
{
    COMPREPLY=($(compgen -W " --DryRun --Login --Password" -- ${cur}))
}
AcceptNetPeering()
{
    COMPREPLY=($(compgen -W " --DryRun --NetPeeringId" -- ${cur}))
}
# OUTSCALE FCU
AcceptVpcPeeringConnection () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcPeeringConnectionId " -- ${cur}))
}
AllocateAddress () 	{
    COMPREPLY=($(compgen -W " --Domain --DryRun " -- ${cur}))
}
AssignPrivateIpAddresses () 	{
    COMPREPLY=($(compgen -W " --AllowReassignment --NetworkInterfaceId --PrivateIpAddresses --SecondaryPrivateIpAddressCount " -- ${cur}))
}
AssociateAddress () 	{
    COMPREPLY=($(compgen -W " --AllocationId --AllowReassociation --DryRun --InstanceId --NetworkInterfaceId --PrivateIpAddress --PublicIp " -- ${cur}))
}
AssociateDhcpOptions () 	{
    COMPREPLY=($(compgen -W " --DhcpOptionsId --DryRun --VpcId " -- ${cur}))
}
AssociateRouteTable () 	{
    COMPREPLY=($(compgen -W " --DryRun --RouteTableId --SubnetId " -- ${cur}))
}
AttachInternetGateway () 	{
    COMPREPLY=($(compgen -W " --DryRun --InternetGatewayId --VpcId " -- ${cur}))
}
AttachNetworkInterface () 	{
    COMPREPLY=($(compgen -W " --DeviceIndex --DryRun --InstanceId --NetworkInterfaceId " -- ${cur}))
}
AttachVolume () 	{
    COMPREPLY=($(compgen -W " --Device --DryRun --InstanceId --VolumeId " -- ${cur}))
}
AttachVpnGateway () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcId --VpnGatewayId " -- ${cur}))
}
AuthorizeSecurityGroupEgress () 	{
    COMPREPLY=($(compgen -W " --CidrIp --DryRun --FromPort --GroupId --IpPermissions --IpProtocol --SourceSecurityGroupName --SourceSecurityGroupOwnerId --ToPort " -- ${cur}))
}
AuthorizeSecurityGroupIngress () 	{
    COMPREPLY=($(compgen -W " --CidrIp --DryRun --FromPort --GroupId --GroupName --IpPermissions --IpProtocol --SourceSecurityGroupName --SourceSecurityGroupOwnerId --ToPort " -- ${cur}))
}
BundleInstance () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceId --Storage " -- ${cur}))
}
CancelBundleTask () 	{
    COMPREPLY=($(compgen -W " --BundleId --DryRun " -- ${cur}))
}
CancelConversionTask () 	{
    COMPREPLY=($(compgen -W " --ConversionTaskId --DryRun --ReasonMessage " -- ${cur}))
}
CancelExportTask () 	{
    COMPREPLY=($(compgen -W " --ExportTaskId " -- ${cur}))
}
CancelReservedInstancesListing () 	{
    COMPREPLY=($(compgen -W " --ReservedInstancesListingId " -- ${cur}))
}
CancelSpotInstanceRequests () 	{
    COMPREPLY=($(compgen -W " --DryRun --SpotInstanceRequestIds " -- ${cur}))
}
ConfirmProductInstance () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceId --ProductCode " -- ${cur}))
}
CopyImage () 	{
    COMPREPLY=($(compgen -W " --ClientToken --Description --DryRun --Name --SourceImageId --SourceRegion " -- ${cur}))
}
CopySnapshot () 	{
    COMPREPLY=($(compgen -W " --Description --DestinationRegion --DryRun --PresignedUrl --SourceRegion --SourceSnapshotId " -- ${cur}))
}
CreateCustomerGateway () 	{
    COMPREPLY=($(compgen -W " --BgpAsn --DryRun --PublicIp --Type " -- ${cur}))
}
CreateDhcpOptions () 	{
    COMPREPLY=($(compgen -W " --DhcpConfigurations --DryRun " -- ${cur}))
}
CreateImage () 	{
    COMPREPLY=($(compgen -W " --BlockDeviceMappings --Description --DryRun --InstanceId --Name --NoReboot " -- ${cur}))
}
CreateInstanceExportTask () 	{
    COMPREPLY=($(compgen -W " --Description --ExportToS3Task --InstanceId --TargetEnvironment " -- ${cur}))
}
CreateInternetGateway () 	{
    COMPREPLY=($(compgen -W " --DryRun " -- ${cur}))
}
CreateKeyPair () 	{
    COMPREPLY=($(compgen -W " --DryRun --KeyName " -- ${cur}))
}
CreateNetworkAcl () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcId " -- ${cur}))
}
CreateNetworkAclEntry () 	{
    COMPREPLY=($(compgen -W " --CidrBlock --DryRun --Egress --IcmpTypeCode --NetworkAclId --PortRange --Protocol --RuleAction --RuleNumber " -- ${cur}))
}
CreateNetworkInterface () 	{
    COMPREPLY=($(compgen -W " --Description --DryRun --Groups --PrivateIpAddress --PrivateIpAddresses --SecondaryPrivateIpAddressCount --SubnetId " -- ${cur}))
}
CreatePlacementGroup () 	{
    COMPREPLY=($(compgen -W " --DryRun --GroupName --Strategy " -- ${cur}))
}
CreateReservedInstancesListing () 	{
    COMPREPLY=($(compgen -W " --ClientToken --InstanceCount --PriceSchedules --ReservedInstancesId " -- ${cur}))
}
CreateRoute () 	{
    COMPREPLY=($(compgen -W " --DestinationCidrBlock --DryRun --GatewayId --InstanceId --NetworkInterfaceId --RouteTableId --VpcPeeringConnectionId " -- ${cur}))
}
CreateRouteTable () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcId " -- ${cur}))
}
CreateSecurityGroup () 	{
    COMPREPLY=($(compgen -W " --Description --DryRun --GroupName --VpcId " -- ${cur}))
}
CreateSnapshot () 	{
    COMPREPLY=($(compgen -W " --Description --DryRun --VolumeId " -- ${cur}))
}
CreateSpotDatafeedSubscription () 	{
    COMPREPLY=($(compgen -W " --Bucket --DryRun --Prefix " -- ${cur}))
}
CreateSubnet () 	{
    COMPREPLY=($(compgen -W " --AvailabilityZone --CidrBlock --DryRun --VpcId " -- ${cur}))
}
CreateTags () 	{
    COMPREPLY=($(compgen -W " --DryRun --Resources --Tags " -- ${cur}))
}
CreateVolume () 	{
    COMPREPLY=($(compgen -W " --AvailabilityZone --DryRun --Encrypted --Iops --Size --SnapshotId --VolumeType " -- ${cur}))
}
CreateVpc () 	{
    COMPREPLY=($(compgen -W " --CidrBlock --DryRun --InstanceTenancy " -- ${cur}))
}
CreateVpcPeeringConnection () 	{
    COMPREPLY=($(compgen -W " --DryRun --PeerOwnerId --PeerVpcId --VpcId " -- ${cur}))
}
CreateVpnConnection () 	{
    COMPREPLY=($(compgen -W " --CustomerGatewayId --DryRun --Options --Type --VpnGatewayId " -- ${cur}))
}
CreateVpnConnectionRoute () 	{
    COMPREPLY=($(compgen -W " --DestinationCidrBlock --VpnConnectionId " -- ${cur}))
}
CreateVpnGateway () 	{
    COMPREPLY=($(compgen -W " --AvailabilityZone --DryRun --Type " -- ${cur}))
}
DeleteCustomerGateway () 	{
    COMPREPLY=($(compgen -W " --CustomerGatewayId --DryRun " -- ${cur}))
}
DeleteDhcpOptions () 	{
    COMPREPLY=($(compgen -W " --DhcpOptionsId --DryRun " -- ${cur}))
}
DeleteInternetGateway () 	{
    COMPREPLY=($(compgen -W " --DryRun --InternetGatewayId " -- ${cur}))
}
DeleteKeyPair () 	{
    COMPREPLY=($(compgen -W " --DryRun --KeyName " -- ${cur}))
}
DeleteNetworkAcl () 	{
    COMPREPLY=($(compgen -W " --DryRun --NetworkAclId " -- ${cur}))
}
DeleteNetworkAclEntry () 	{
    COMPREPLY=($(compgen -W " --DryRun --Egress --NetworkAclId --RuleNumber " -- ${cur}))
}
DeleteNetworkInterface () 	{
    COMPREPLY=($(compgen -W " --DryRun --NetworkInterfaceId " -- ${cur}))
}
DeletePlacementGroup () 	{
    COMPREPLY=($(compgen -W " --DryRun --GroupName " -- ${cur}))
}
DeleteRoute () 	{
    COMPREPLY=($(compgen -W " --DestinationCidrBlock --DryRun --RouteTableId " -- ${cur}))
}
DeleteRouteTable () 	{
    COMPREPLY=($(compgen -W " --DryRun --RouteTableId " -- ${cur}))
}
DeleteSecurityGroup () 	{
    COMPREPLY=($(compgen -W " --DryRun --GroupId --GroupName " -- ${cur}))
}
DeleteSnapshot () 	{
    COMPREPLY=($(compgen -W " --DryRun --SnapshotId " -- ${cur}))
}
DeleteSpotDatafeedSubscription () 	{
    COMPREPLY=($(compgen -W " --DryRun " -- ${cur}))
}
DeleteSubnet () 	{
    COMPREPLY=($(compgen -W " --DryRun --SubnetId " -- ${cur}))
}
DeleteTags () 	{
    COMPREPLY=($(compgen -W " --DryRun --Resources --Tags " -- ${cur}))
}
DeleteVolume () 	{
    COMPREPLY=($(compgen -W " --DryRun --VolumeId " -- ${cur}))
}
DeleteVpc () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcId " -- ${cur}))
}
DeleteVpcPeeringConnection () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcPeeringConnectionId " -- ${cur}))
}
DeleteVpnConnection () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpnConnectionId " -- ${cur}))
}
DeleteVpnConnectionRoute () 	{
    COMPREPLY=($(compgen -W " --DestinationCidrBlock --VpnConnectionId " -- ${cur}))
}
DeleteVpnGateway () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpnGatewayId " -- ${cur}))
}
DeregisterImage () 	{
    COMPREPLY=($(compgen -W " --DryRun --ImageId " -- ${cur}))
}
DescribeAccountAttributes () 	{
    COMPREPLY=($(compgen -W " --AttributeNames --DryRun " -- ${cur}))
}
DescribeAddresses () 	{
    COMPREPLY=($(compgen -W " --AllocationIds --DryRun --Filters --PublicIps " -- ${cur}))
}
DescribeAvailabilityZones () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --ZoneNames " -- ${cur}))
}
DescribeBundleTasks () 	{
    COMPREPLY=($(compgen -W " --BundleIds --DryRun --Filters " -- ${cur}))
}
DescribeConversionTasks () 	{
    COMPREPLY=($(compgen -W " --ConversionTaskIds --DryRun --Filters " -- ${cur}))
}
DescribeCustomerGateways () 	{
    COMPREPLY=($(compgen -W " --CustomerGatewayIds --DryRun --Filters " -- ${cur}))
}
DescribeDhcpOptions () 	{
    COMPREPLY=($(compgen -W " --DhcpOptionsIds --DryRun --Filters " -- ${cur}))
}
DescribeExportTasks () 	{
    COMPREPLY=($(compgen -W " --ExportTaskIds " -- ${cur}))
}
DescribeImageAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --ImageId " -- ${cur}))
}
DescribeImages () 	{
    COMPREPLY=($(compgen -W " --DryRun --ExecutableUsers --Filters --ImageIds --Owners " -- ${cur}))
}
DescribeInstanceAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --InstanceId " -- ${cur}))
}
DescribeInstanceStatus () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --IncludeAllInstances --InstanceIds --MaxResults --NextToken " -- ${cur}))
}
DescribeInstances () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --InstanceIds --MaxResults --NextToken " -- ${cur}))
}
DescribeInternetGateways () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --InternetGatewayIds " -- ${cur}))
}
DescribeKeyPairs () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --KeyNames " -- ${cur}))
}
DescribeNetworkAcls () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --NetworkAclIds " -- ${cur}))
}
DescribeNetworkInterfaceAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --NetworkInterfaceId " -- ${cur}))
}
DescribeNetworkInterfaces () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --NetworkInterfaceIds " -- ${cur}))
}
DescribePlacementGroups () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --GroupNames " -- ${cur}))
}
DescribeRegions () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --RegionNames " -- ${cur}))
}
DescribeReservedInstances () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --OfferingType --ReservedInstancesIds " -- ${cur}))
}
DescribeReservedInstancesListings () 	{
    COMPREPLY=($(compgen -W " --Filters --ReservedInstancesId --ReservedInstancesListingId " -- ${cur}))
}
DescribeReservedInstancesModifications () 	{
    COMPREPLY=($(compgen -W " --Filters --NextToken --ReservedInstancesModificationIds " -- ${cur}))
}
DescribeReservedInstancesOfferings () 	{
    COMPREPLY=($(compgen -W " --AvailabilityZone --DryRun --Filters --IncludeMarketplace --InstanceTenancy --InstanceType --MaxDuration --MaxInstanceCount --MaxResults --MinDuration --NextToken --OfferingType --ProductDescription --ReservedInstancesOfferingIds " -- ${cur}))
}
DescribeRouteTables () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --RouteTableIds " -- ${cur}))
}
DescribeSecurityGroups () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --GroupIds --GroupNames " -- ${cur}))
}
DescribeSnapshotAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --SnapshotId " -- ${cur}))
}
DescribeSnapshots () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --OwnerIds --RestorableByUserIds --SnapshotIds " -- ${cur}))
}
DescribeSpotDatafeedSubscription () 	{
    COMPREPLY=($(compgen -W " --DryRun " -- ${cur}))
}
DescribeSpotInstanceRequests () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --SpotInstanceRequestIds " -- ${cur}))
}
DescribeSpotPriceHistory () 	{
    COMPREPLY=($(compgen -W " --AvailabilityZone --DryRun --EndTime --Filters --InstanceTypes --MaxResults --NextToken --ProductDescriptions --StartTime " -- ${cur}))
}
DescribeSubnets () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --SubnetIds " -- ${cur}))
}
DescribeTags () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --MaxResults --NextToken " -- ${cur}))
}
DescribeVolumeAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --VolumeId " -- ${cur}))
}
DescribeVolumeStatus () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --MaxResults --NextToken --VolumeIds " -- ${cur}))
}
DescribeVolumes () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --VolumeIds " -- ${cur}))
}
DescribeVpcAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --VpcId " -- ${cur}))
}
DescribeVpcPeeringConnections () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --VpcPeeringConnectionIds " -- ${cur}))
}
DescribeVpcs () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --VpcIds " -- ${cur}))
}
DescribeVpnConnections () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --VpnConnectionIds " -- ${cur}))
}
DescribeVpnGateways () 	{
    COMPREPLY=($(compgen -W " --DryRun --Filters --VpnGatewayIds " -- ${cur}))
}
DetachInternetGateway () 	{
    COMPREPLY=($(compgen -W " --DryRun --InternetGatewayId --VpcId " -- ${cur}))
}
DetachNetworkInterface () 	{
    COMPREPLY=($(compgen -W " --AttachmentId --DryRun --Force " -- ${cur}))
}
DetachVolume () 	{
    COMPREPLY=($(compgen -W " --Device --DryRun --Force --InstanceId --VolumeId " -- ${cur}))
}
DetachVpnGateway () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcId --VpnGatewayId " -- ${cur}))
}
DisableVgwRoutePropagation () 	{
    COMPREPLY=($(compgen -W " --GatewayId --RouteTableId " -- ${cur}))
}
DisassociateAddress () 	{
    COMPREPLY=($(compgen -W " --AssociationId --DryRun --PublicIp " -- ${cur}))
}
DisassociateRouteTable () 	{
    COMPREPLY=($(compgen -W " --AssociationId --DryRun " -- ${cur}))
}
EnableVgwRoutePropagation () 	{
    COMPREPLY=($(compgen -W " --GatewayId --RouteTableId " -- ${cur}))
}
EnableVolumeIO () 	{
    COMPREPLY=($(compgen -W " --DryRun --VolumeId " -- ${cur}))
}
GetConsoleOutput () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceId " -- ${cur}))
}
GetPasswordData () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceId " -- ${cur}))
}
ImportInstance () 	{
    COMPREPLY=($(compgen -W " --Description --DiskImages --DryRun --LaunchSpecification --Platform " -- ${cur}))
}
ImportKeyPair () 	{
    COMPREPLY=($(compgen -W " --DryRun --KeyName --PublicKeyMaterial " -- ${cur}))
}
ImportVolume () 	{
    COMPREPLY=($(compgen -W " --AvailabilityZone --Description --DryRun --Image --Volume " -- ${cur}))
}
ModifyImageAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --Description --DryRun --ImageId --LaunchPermission --OperationType --ProductCodes --UserGroups --UserIds --Value " -- ${cur}))
}
ModifyInstanceAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --BlockDeviceMappings --DisableApiTermination --DryRun --EbsOptimized --Groups --InstanceId --InstanceInitiatedShutdownBehavior --InstanceType --Kernel --Ramdisk --SourceDestCheck --SriovNetSupport --UserData --Value " -- ${cur}))
}
ModifyNetworkInterfaceAttribute () 	{
    COMPREPLY=($(compgen -W " --Attachment --Description --DryRun --Groups --NetworkInterfaceId --SourceDestCheck " -- ${cur}))
}
ModifyReservedInstances () 	{
    COMPREPLY=($(compgen -W " --ClientToken --ReservedInstancesIds --TargetConfigurations " -- ${cur}))
}
ModifySnapshotAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --CreateVolumePermission --DryRun --GroupNames --OperationType --SnapshotId --UserIds " -- ${cur}))
}
ModifySubnetAttribute () 	{
    COMPREPLY=($(compgen -W " --MapPublicIpOnLaunch --SubnetId " -- ${cur}))
}
ModifyVolumeAttribute () 	{
    COMPREPLY=($(compgen -W " --AutoEnableIO --DryRun --VolumeId " -- ${cur}))
}
ModifyVpcAttribute () 	{
    COMPREPLY=($(compgen -W " --EnableDnsHostnames --EnableDnsSupport --VpcId " -- ${cur}))
}
MonitorInstances () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceIds " -- ${cur}))
}
PurchaseReservedInstancesOffering () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceCount --LimitPrice --ReservedInstancesOfferingId " -- ${cur}))
}
RebootInstances () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceIds " -- ${cur}))
}
RegisterImage () 	{
    COMPREPLY=($(compgen -W " --Architecture --BlockDeviceMappings --Description --DryRun --ImageLocation --KernelId --Name --RamdiskId --RootDeviceName --SriovNetSupport --VirtualizationType " -- ${cur}))
}
RejectVpcPeeringConnection () 	{
    COMPREPLY=($(compgen -W " --DryRun --VpcPeeringConnectionId " -- ${cur}))
}
ReleaseAddress () 	{
    COMPREPLY=($(compgen -W " --AllocationId --DryRun --PublicIp " -- ${cur}))
}
ReplaceNetworkAclAssociation () 	{
    COMPREPLY=($(compgen -W " --AssociationId --DryRun --NetworkAclId " -- ${cur}))
}
ReplaceNetworkAclEntry () 	{
    COMPREPLY=($(compgen -W " --CidrBlock --DryRun --Egress --IcmpTypeCode --NetworkAclId --PortRange --Protocol --RuleAction --RuleNumber " -- ${cur}))
}
ReplaceRoute () 	{
    COMPREPLY=($(compgen -W " --DestinationCidrBlock --DryRun --GatewayId --InstanceId --NetworkInterfaceId --RouteTableId --VpcPeeringConnectionId " -- ${cur}))
}
ReplaceRouteTableAssociation () 	{
    COMPREPLY=($(compgen -W " --AssociationId --DryRun --RouteTableId " -- ${cur}))
}
ReportInstanceStatus () 	{
    COMPREPLY=($(compgen -W " --Description --DryRun --EndTime --Instances --ReasonCodes --StartTime --Status " -- ${cur}))
}
RequestSpotInstances () 	{
    COMPREPLY=($(compgen -W " --AvailabilityZoneGroup --DryRun --InstanceCount --LaunchGroup --LaunchSpecification --SpotPrice --Type --ValidFrom --ValidUntil " -- ${cur}))
}
ResetImageAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --ImageId " -- ${cur}))
}
ResetInstanceAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --InstanceId " -- ${cur}))
}
ResetNetworkInterfaceAttribute () 	{
    COMPREPLY=($(compgen -W " --DryRun --NetworkInterfaceId --SourceDestCheck " -- ${cur}))
}
ResetSnapshotAttribute () 	{
    COMPREPLY=($(compgen -W " --Attribute --DryRun --SnapshotId " -- ${cur}))
}
RevokeSecurityGroupEgress () 	{
    COMPREPLY=($(compgen -W " --CidrIp --DryRun --FromPort --GroupId --IpPermissions --IpProtocol --SourceSecurityGroupName --SourceSecurityGroupOwnerId --ToPort " -- ${cur}))
}
RevokeSecurityGroupIngress () 	{
    COMPREPLY=($(compgen -W " --CidrIp --DryRun --FromPort --GroupId --GroupName --IpPermissions --IpProtocol --SourceSecurityGroupName --SourceSecurityGroupOwnerId --ToPort " -- ${cur}))
}
RunInstances () 	{
    COMPREPLY=($(compgen -W " --AdditionalInfo --BlockDeviceMappings --ClientToken --DisableApiTermination --DryRun --EbsOptimized --IamInstanceProfile --ImageId --InstanceInitiatedShutdownBehavior --InstanceType --KernelId --KeyName --MaxCount --MinCount --Monitoring --NetworkInterfaces --Placement --PrivateIpAddress --RamdiskId --SecurityGroupIds --SecurityGroups --SubnetId --UserData " -- ${cur}))
}
StartInstances () 	{
    COMPREPLY=($(compgen -W " --AdditionalInfo --DryRun --InstanceIds " -- ${cur}))
}
StopInstances () 	{
    COMPREPLY=($(compgen -W " --DryRun --Force --InstanceIds " -- ${cur}))
}
TerminateInstances () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceIds " -- ${cur}))
}
UnassignPrivateIpAddresses () 	{
    COMPREPLY=($(compgen -W " --NetworkInterfaceId --PrivateIpAddresses " -- ${cur}))
}
UnmonitorInstances () 	{
    COMPREPLY=($(compgen -W " --DryRun --InstanceIds " -- ${cur}))
}
#/usr/bin/env bash

_mk_profiles()
{
    cur=${COMP_WORDS[COMP_CWORD]}

    if [ -f ~/.osc/config.json ]; then
	PROFILES=$(cat ~/.osc/config.json | tr -d '\n:'  | sed 's/{[^{}]*}//g' | tr -d "{}\" " | sed 's/,/ /g')
    elif [ -f ~/.osc_sdk/config.json ]; then
	PROFILES=$(cat ~/.osc_sdk/config.json | tr -d '\n:'  | sed 's/{[^{}]*}//g' | tr -d "{}\" " | sed 's/,/ /g')
    fi
    for x in $PROFILES ; do echo --profile=$x ; done
}

_osc_cli()
{
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}
    case ${COMP_CWORD} in
        *)
            case ${prev} in
                api)
                    COMPREPLY=($(compgen -W "
UpdateVpnConnection UpdateVolume UpdateVm UpdateSubnet UpdateSnapshot UpdateServerCertificate UpdateRoutePropagation UpdateRoute UpdateNic UpdateNetAccessPoint UpdateNet UpdateLoadBalancer UpdateListenerRule UpdateImage UpdateFlexibleGpu UpdateDirectLinkInterface UpdateCa UpdateApiAccessRule UpdateApiAccessPolicy UpdateAccount UpdateAccessKey UnlinkVolume UnlinkVirtualGateway UnlinkRouteTable UnlinkPublicIp UnlinkPrivateIps UnlinkNic UnlinkLoadBalancerBackendMachines UnlinkInternetService UnlinkFlexibleGpu StopVms StartVms SendResetPasswordEmail ResetAccountPassword RejectNetPeering RegisterVmsInLoadBalancer RebootVms ReadVpnConnections ReadVolumes ReadVmsState ReadVmsHealth ReadVms ReadVmTypes ReadVirtualGateways ReadTags ReadSubregions ReadSubnets ReadSnapshots ReadSnapshotExportTasks ReadServerCertificates ReadSecurityGroups ReadSecretAccessKey ReadRouteTables ReadRegions ReadQuotas ReadPublicIps ReadPublicIpRanges ReadPublicCatalog ReadProductTypes ReadNics ReadNets ReadNetPeerings ReadNetAccessPoints ReadNetAccessPointServices ReadNatServices ReadLocations ReadLoadBalancers ReadLoadBalancerTags ReadListenerRules ReadKeypairs ReadInternetServices ReadImages ReadImageExportTasks ReadFlexibleGpus ReadFlexibleGpuCatalog ReadDirectLinks ReadDirectLinkInterfaces ReadDhcpOptions ReadConsumptionAccount ReadConsoleOutput ReadClientGateways ReadCatalog ReadCas ReadApiLogs ReadApiAccessRules ReadApiAccessPolicy ReadAdminPassword ReadAccounts ReadAccessKeys LinkVolume LinkVirtualGateway LinkRouteTable LinkPublicIp LinkPrivateIps LinkNic LinkLoadBalancerBackendMachines LinkInternetService LinkFlexibleGpu DeregisterVmsInLoadBalancer DeleteVpnConnectionRoute DeleteVpnConnection DeleteVolume DeleteVms DeleteVirtualGateway DeleteTags DeleteSubnet DeleteSnapshot DeleteServerCertificate DeleteSecurityGroupRule DeleteSecurityGroup DeleteRouteTable DeleteRoute DeletePublicIp DeleteNic DeleteNetPeering DeleteNetAccessPoint DeleteNet DeleteNatService DeleteLoadBalancerTags DeleteLoadBalancerPolicy DeleteLoadBalancerListeners DeleteLoadBalancer DeleteListenerRule DeleteKeypair DeleteInternetService DeleteImage DeleteFlexibleGpu DeleteExportTask DeleteDirectLinkInterface DeleteDirectLink DeleteDhcpOptions DeleteClientGateway DeleteCa DeleteApiAccessRule DeleteAccessKey CreateVpnConnectionRoute CreateVpnConnection CreateVolume CreateVms CreateVirtualGateway CreateTags CreateSubnet CreateSnapshotExportTask CreateSnapshot CreateServerCertificate CreateSecurityGroupRule CreateSecurityGroup CreateRouteTable CreateRoute CreatePublicIp CreateNic CreateNetPeering CreateNetAccessPoint CreateNet CreateNatService CreateLoadBalancerTags CreateLoadBalancerPolicy CreateLoadBalancerListeners CreateLoadBalancer CreateListenerRule CreateKeypair CreateInternetService CreateImageExportTask CreateImage CreateFlexibleGpu CreateDirectLinkInterface CreateDirectLink CreateDhcpOptions CreateClientGateway CreateCa CreateApiAccessRule CreateAccount CreateAccessKey CheckAuthentication AcceptNetPeering" -- ${cur}))
	;;
fcu)
COMPREPLY=($(compgen -W "AcceptVpcPeeringConnection AllocateAddress AssignPrivateIpAddresses AssociateAddress AssociateDhcpOptions AssociateRouteTable AttachInternetGateway AttachNetworkInterface AttachVolume AttachVpnGateway AuthorizeSecurityGroupEgress AuthorizeSecurityGroupIngress BundleInstance CancelBundleTask CancelConversionTask CancelExportTask CancelReservedInstancesListing CancelSpotInstanceRequests ConfirmProductInstance CopyImage CopySnapshot CreateCustomerGateway CreateDhcpOptions CreateImage CreateInstanceExportTask CreateInternetGateway CreateKeyPair CreateNetworkAcl CreateNetworkAclEntry CreateNetworkInterface CreatePlacementGroup CreateReservedInstancesListing CreateRoute CreateRouteTable CreateSecurityGroup CreateSnapshot CreateSpotDatafeedSubscription CreateSubnet CreateTags CreateVolume CreateVpc CreateVpcPeeringConnection CreateVpnConnection CreateVpnConnectionRoute CreateVpnGateway DeleteCustomerGateway DeleteDhcpOptions DeleteInternetGateway DeleteKeyPair DeleteNetworkAcl DeleteNetworkAclEntry DeleteNetworkInterface DeletePlacementGroup DeleteRoute DeleteRouteTable DeleteSecurityGroup DeleteSnapshot DeleteSpotDatafeedSubscription DeleteSubnet DeleteTags DeleteVolume DeleteVpc DeleteVpcPeeringConnection DeleteVpnConnection DeleteVpnConnectionRoute DeleteVpnGateway DeregisterImage DescribeAccountAttributes DescribeAddresses DescribeAvailabilityZones DescribeBundleTasks DescribeConversionTasks DescribeCustomerGateways DescribeDhcpOptions DescribeExportTasks DescribeImageAttribute DescribeImages DescribeInstanceAttribute DescribeInstanceStatus DescribeInstances DescribeInternetGateways DescribeKeyPairs DescribeNetworkAcls DescribeNetworkInterfaceAttribute DescribeNetworkInterfaces DescribePlacementGroups DescribeRegions DescribeReservedInstances DescribeReservedInstancesListings DescribeReservedInstancesModifications DescribeReservedInstancesOfferings DescribeRouteTables DescribeSecurityGroups DescribeSnapshotAttribute DescribeSnapshots DescribeSpotDatafeedSubscription DescribeSpotInstanceRequests DescribeSpotPriceHistory DescribeSubnets DescribeTags DescribeVolumeAttribute DescribeVolumeStatus DescribeVolumes DescribeVpcAttribute DescribeVpcPeeringConnections DescribeVpcs DescribeVpnConnections DescribeVpnGateways DetachInternetGateway DetachNetworkInterface DetachVolume DetachVpnGateway DisableVgwRoutePropagation DisassociateAddress DisassociateRouteTable EnableVgwRoutePropagation EnableVolumeIO GetConsoleOutput GetPasswordData ImportInstance ImportKeyPair ImportVolume ModifyImageAttribute ModifyInstanceAttribute ModifyNetworkInterfaceAttribute ModifyReservedInstances ModifySnapshotAttribute ModifySubnetAttribute ModifyVolumeAttribute ModifyVpcAttribute MonitorInstances PurchaseReservedInstancesOffering RebootInstances RegisterImage RejectVpcPeeringConnection ReleaseAddress ReplaceNetworkAclAssociation ReplaceNetworkAclEntry ReplaceRoute ReplaceRouteTableAssociation ReportInstanceStatus RequestSpotInstances ResetImageAttribute ResetInstanceAttribute ResetNetworkInterfaceAttribute ResetSnapshotAttribute RevokeSecurityGroupEgress RevokeSecurityGroupIngress RunInstances StartInstances StopInstances TerminateInstances UnassignPrivateIpAddresses UnmonitorInstances" -- ${cur}))
;;

AcceptVpcPeeringConnection | AllocateAddress | AssignPrivateIpAddresses | AssociateAddress | AssociateDhcpOptions | AssociateRouteTable | AttachInternetGateway | AttachNetworkInterface | AttachVolume | AttachVpnGateway | AuthorizeSecurityGroupEgress | AuthorizeSecurityGroupIngress | BundleInstance | CancelBundleTask | CancelConversionTask | CancelExportTask | CancelReservedInstancesListing | CancelSpotInstanceRequests | ConfirmProductInstance | CopyImage | CopySnapshot | CreateCustomerGateway | CreateDhcpOptions | CreateImage | CreateInstanceExportTask | CreateInternetGateway | CreateKeyPair | CreateNetworkAcl | CreateNetworkAclEntry | CreateNetworkInterface | CreatePlacementGroup | CreateReservedInstancesListing | CreateRoute | CreateRouteTable | CreateSecurityGroup | CreateSnapshot | CreateSpotDatafeedSubscription | CreateSubnet | CreateTags | CreateVolume | CreateVpc | CreateVpcPeeringConnection | CreateVpnConnection | CreateVpnConnectionRoute | CreateVpnGateway | DeleteCustomerGateway | DeleteDhcpOptions | DeleteInternetGateway | DeleteKeyPair | DeleteNetworkAcl | DeleteNetworkAclEntry | DeleteNetworkInterface | DeletePlacementGroup | DeleteRoute | DeleteRouteTable | DeleteSecurityGroup | DeleteSnapshot | DeleteSpotDatafeedSubscription | DeleteSubnet | DeleteTags | DeleteVolume | DeleteVpc | DeleteVpcPeeringConnection | DeleteVpnConnection | DeleteVpnConnectionRoute | DeleteVpnGateway | DeregisterImage | DescribeAccountAttributes | DescribeAddresses | DescribeAvailabilityZones | DescribeBundleTasks | DescribeConversionTasks | DescribeCustomerGateways | DescribeDhcpOptions | DescribeExportTasks | DescribeImageAttribute | DescribeImages | DescribeInstanceAttribute | DescribeInstanceStatus | DescribeInstances | DescribeInternetGateways | DescribeKeyPairs | DescribeNetworkAcls | DescribeNetworkInterfaceAttribute | DescribeNetworkInterfaces | DescribePlacementGroups | DescribeRegions | DescribeReservedInstances | DescribeReservedInstancesListings | DescribeReservedInstancesModifications | DescribeReservedInstancesOfferings | DescribeRouteTables | DescribeSecurityGroups | DescribeSnapshotAttribute | DescribeSnapshots | DescribeSpotDatafeedSubscription | DescribeSpotInstanceRequests | DescribeSpotPriceHistory | DescribeSubnets | DescribeTags | DescribeVolumeAttribute | DescribeVolumeStatus | DescribeVolumes | DescribeVpcAttribute | DescribeVpcPeeringConnections | DescribeVpcs | DescribeVpnConnections | DescribeVpnGateways | DetachInternetGateway | DetachNetworkInterface | DetachVolume | DetachVpnGateway | DisableVgwRoutePropagation | DisassociateAddress | DisassociateRouteTable | EnableVgwRoutePropagation | EnableVolumeIO | GetConsoleOutput | GetPasswordData | ImportInstance | ImportKeyPair | ImportVolume | ModifyImageAttribute | ModifyInstanceAttribute | ModifyNetworkInterfaceAttribute | ModifyReservedInstances | ModifySnapshotAttribute | ModifySubnetAttribute | ModifyVolumeAttribute | ModifyVpcAttribute | MonitorInstances | PurchaseReservedInstancesOffering | RebootInstances | RegisterImage | RejectVpcPeeringConnection | ReleaseAddress | ReplaceNetworkAclAssociation | ReplaceNetworkAclEntry | ReplaceRoute | ReplaceRouteTableAssociation | ReportInstanceStatus | RequestSpotInstances | ResetImageAttribute | ResetInstanceAttribute | ResetNetworkInterfaceAttribute | ResetSnapshotAttribute | RevokeSecurityGroupEgress | RevokeSecurityGroupIngress | RunInstances | StartInstances | StopInstances | TerminateInstances | UnassignPrivateIpAddresses | UnmonitorInstances)
eval ${prev}
;;
UpdateVpnConnection | UpdateVolume | UpdateVm | UpdateSubnet | UpdateSnapshot | UpdateServerCertificate | UpdateRoutePropagation | UpdateRoute | UpdateNic | UpdateNetAccessPoint | UpdateNet | UpdateLoadBalancer | UpdateListenerRule | UpdateImage | UpdateFlexibleGpu | UpdateDirectLinkInterface | UpdateCa | UpdateApiAccessRule | UpdateApiAccessPolicy | UpdateAccount | UpdateAccessKey | UnlinkVolume | UnlinkVirtualGateway | UnlinkRouteTable | UnlinkPublicIp | UnlinkPrivateIps | UnlinkNic | UnlinkLoadBalancerBackendMachines | UnlinkInternetService | UnlinkFlexibleGpu | StopVms | StartVms | SendResetPasswordEmail | ResetAccountPassword | RejectNetPeering | RegisterVmsInLoadBalancer | RebootVms | ReadVpnConnections | ReadVolumes | ReadVmsState | ReadVmsHealth | ReadVms | ReadVmTypes | ReadVirtualGateways | ReadTags | ReadSubregions | ReadSubnets | ReadSnapshots | ReadSnapshotExportTasks | ReadServerCertificates | ReadSecurityGroups | ReadSecretAccessKey | ReadRouteTables | ReadRegions | ReadQuotas | ReadPublicIps | ReadPublicIpRanges | ReadPublicCatalog | ReadProductTypes | ReadNics | ReadNets | ReadNetPeerings | ReadNetAccessPoints | ReadNetAccessPointServices | ReadNatServices | ReadLocations | ReadLoadBalancers | ReadLoadBalancerTags | ReadListenerRules | ReadKeypairs | ReadInternetServices | ReadImages | ReadImageExportTasks | ReadFlexibleGpus | ReadFlexibleGpuCatalog | ReadDirectLinks | ReadDirectLinkInterfaces | ReadDhcpOptions | ReadConsumptionAccount | ReadConsoleOutput | ReadClientGateways | ReadCatalog | ReadCas | ReadApiLogs | ReadApiAccessRules | ReadApiAccessPolicy | ReadAdminPassword | ReadAccounts | ReadAccessKeys | LinkVolume | LinkVirtualGateway | LinkRouteTable | LinkPublicIp | LinkPrivateIps | LinkNic | LinkLoadBalancerBackendMachines | LinkInternetService | LinkFlexibleGpu | DeregisterVmsInLoadBalancer | DeleteVpnConnectionRoute | DeleteVpnConnection | DeleteVolume | DeleteVms | DeleteVirtualGateway | DeleteTags | DeleteSubnet | DeleteSnapshot | DeleteServerCertificate | DeleteSecurityGroupRule | DeleteSecurityGroup | DeleteRouteTable | DeleteRoute | DeletePublicIp | DeleteNic | DeleteNetPeering | DeleteNetAccessPoint | DeleteNet | DeleteNatService | DeleteLoadBalancerTags | DeleteLoadBalancerPolicy | DeleteLoadBalancerListeners | DeleteLoadBalancer | DeleteListenerRule | DeleteKeypair | DeleteInternetService | DeleteImage | DeleteFlexibleGpu | DeleteExportTask | DeleteDirectLinkInterface | DeleteDirectLink | DeleteDhcpOptions | DeleteClientGateway | DeleteCa | DeleteApiAccessRule | DeleteAccessKey | CreateVpnConnectionRoute | CreateVpnConnection | CreateVolume | CreateVms | CreateVirtualGateway | CreateTags | CreateSubnet | CreateSnapshotExportTask | CreateSnapshot | CreateServerCertificate | CreateSecurityGroupRule | CreateSecurityGroup | CreateRouteTable | CreateRoute | CreatePublicIp | CreateNic | CreateNetPeering | CreateNetAccessPoint | CreateNet | CreateNatService | CreateLoadBalancerTags | CreateLoadBalancerPolicy | CreateLoadBalancerListeners | CreateLoadBalancer | CreateListenerRule | CreateKeypair | CreateInternetService | CreateImageExportTask | CreateImage | CreateFlexibleGpu | CreateDirectLinkInterface | CreateDirectLink | CreateDhcpOptions | CreateClientGateway | CreateCa | CreateApiAccessRule | CreateAccount | CreateAccessKey | CheckAuthentication | AcceptNetPeering)
		    eval ${prev}
		    ;;
		    *)
			PROFILES=$(_mk_profiles)
			COMPREPLY=($(compgen -W "api icu lbu directlink eim okms fcu $PROFILES --help --login= --password= --authentication_method=password --authentication_method=accesskey" -- ${cur}))
		    ;;
            esac
            ;;
    esac
}

complete -F _osc_cli osc-cli
complete -F _osc_cli osc-cli-x86_64.AppImage
complete -F _osc_cli ./osc-cli-x86_64.AppImage
