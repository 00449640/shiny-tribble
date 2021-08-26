function Getsetting {
    try 
        {
        $SettingsFile = "C:\temp\POC\POC_settings.json"
        if (!(Get-Item -Path $SettingsFile -ErrorAction SilentlyContinue))
            {
             Write-Error "$SettingsFile findes ikke" -ErrorAction Stop   
            }
        else 
            {
            Write-Host "$Json Findes, benytter json til settings.." -ForegroundColor Green
             $Settings = Get-Content $SettingsFile -Raw 
             $Script:settings = $Settings | ConvertFrom-Json
            }
        }
            catch
            {
            Write-Error $_
            }
        
    }

function Import-POCVM {
    param (
        
    )
    
}
function Check-VMSwitches {

    [CmdletBinding()]
    param (
        
    )
    
    begin {
        
    }
    
    process {
        $VMSwitch = "Internal Switch"
        $VMNetAdapter = Get-VMNetworkAdapter -VMName $Vmname | Select-Object *
       
        #Checking VMSwitch
        if ($VMNetAdapter.switchname -ne $VMSwitch)
            {
                "Connect to Wrong Switch: " + $VMNetAdapter.switchname
                "Connecting to: " + $VMSwitch
                Connect-VMNetworkAdapter -SwitchName $VMSwitch -VMName $Vmname
                $VMNetAdapter = Get-VMNetworkAdapter -VMName $Vmname | Select-Object *
            }
        
    }
    
    end {
        
    }
}

function Check-VM {
    [CmdletBinding()]
    param (
        $Script:VM = (Get-VM | Out-GridView -OutputMode Single -title "Choose VM"),
        #$Cred = (Get-Credential -Credential administrator),
        #$DomainCred = (Get-Credential -credential "Administrator@POC"),
        $VMSwitches = (Get-VMSwitch),
        $DomainName = "POC",
        $FQDN = "POC.Local",
        $DC = "DC01"
    )
    
    begin {
        
    }
    
    process {
        
switch ($Script:VM.Name)
    {
    Router { 
        
        $Vmname = $Script:VM.Name
        $vm = Get-VM $Vmname
        Check-VMState
        
        $Script:PSSession = New-PSSession -VMName $Vmname -Credential $Cred
        $VMNetAdapter = Get-VMNetworkAdapter -VMName $Vmname | Select-Object *

switch ($VMNetAdapter.switchname) 
    {
        "Internal Switch" 
    {
        
        
        $Netadapter = $VMNetAdapter  | where switchname -eq $_
        $IP = "10.144.143.200"
        $Prefix = "20"
        #lav pssession til maskine og kontrollere
        
                 
                 "Connecting to $vmname"
            
             invoke-command -Session $Script:PSSession -ArgumentList $Netadapter, $IP, $Prefix -ScriptBlock {
                 param ($Netadapter, $IP, $Prefix)
                 "Connected Successfully"
                 $currentInterfacealias = Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress
                 if ($currentInterfacealias.InterfaceAlias -ne $Netadapter.SwitchName)
                 {
                     "Netadapter name is " +  $currentInterfacealias.InterfaceAlias
                     "Changing to " + $Netadapter.SwitchName
                 Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress | Rename-NetAdapter -NewName $Netadapter.SwitchName 
                (Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress).Name
                }
                $EthernetConf = Get-NetIPConfiguration | where InterfaceAlias -eq $Netadapter.SwitchName
                if ($EthernetConf.IPv4Address.IPAddress -ne $ip)
        {
             $EthernetConf.InterfaceAlias +" ip is " + $EthernetConf.IPv4Address.IPAddress
            "Changing ip to: " + $ip
            Remove-NetIPAddress -InterfaceAlias $EthernetConf.InterfaceAlias -Confirm:$false
            New-NetIPAddress -InterfaceAlias $Netadapter.switchname -IPAddress $IP -PrefixLength $Prefix -Confirm:$false
        }
        else 
        {"IP OK"}     
             
        }
    
    }
    "Host" 
    {

         $Netadapter = $VMNetAdapter  | where switchname -eq $_
         
         "Connecting to $vmname"
    
     invoke-command -Session $Script:PSSession -ArgumentList $Netadapter, $IP, $Prefix -ScriptBlock {
         param ($Netadapter, $IP, $Prefix)
         "Connected Successfully"
         $currentInterfacealias = Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress
         if ($currentInterfacealias.InterfaceAlias -ne $Netadapter.SwitchName)
         {
             "Netadapter name is " +  $currentInterfacealias.InterfaceAlias
             "Changing to " + $Netadapter.SwitchName
         Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress | Rename-NetAdapter -NewName $Netadapter.SwitchName 
        (Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress).Name
        }
        $EthernetConf = Get-NetIPConfiguration | where InterfaceAlias -eq $Netadapter.SwitchName
        $EthernetConf | Set-NetIPInterface -Dhcp Enabled
         
}
        }
        Default 
                {
                    "Wrong Switch"
                    Connect-VMNetworkAdapter $
                    
                }

    }
        #Check ComputerName
        Check-POCComputerName

    }
    "DC01"
    {
        #Checking DC01
        $Vmname = $Script:VM.Name
        Check-VMState
        New-POCPSession
        $VMSwitch = "Internal Switch" 
        $VMNetAdapter = Get-VMNetworkAdapter -VMName $Vmname | Select-Object *
       
        #Checking VMSwitch
        if ($VMNetAdapter.switchname -ne $VMSwitch)
            {
                "Connect to Wrong Switch: " + $VMNetAdapter.switchname
                "Connecting to: " + $VMSwitch
                Connect-VMNetworkAdapter -SwitchName $VMSwitch -VMName $Vmname
                $VMNetAdapter = Get-VMNetworkAdapter -VMName $Vmname | Select-Object *
            }

        switch ($VMNetAdapter.switchname) 
        {
            "Internal Switch" 
        {
            Check-POCEthernet
        }
            Default {"Connected to wrong Switch: " + $VMNetAdapter.switchname }
        } 
        Check-POCComputerName
        Check-POCFeatures
        Check-POCDomain
    }
    Default 
    {
        $Vmname = $Script:VM.Name
        Check-VMState
        $VMSwitch = "Internal Switch"
        $VMNetAdapter = Get-VMNetworkAdapter -VMName $Vmname | Select-Object *
       
        #Checking VMSwitch
        if ($VMNetAdapter.switchname -ne $VMSwitch)
            {
                "Connect to Wrong Switch: " + $VMNetAdapter.switchname
                "Connecting to: " + $VMSwitch
                Connect-VMNetworkAdapter -SwitchName $VMSwitch -VMName $Vmname
                $VMNetAdapter = Get-VMNetworkAdapter -VMName $Vmname | Select-Object *
            }
        
        New-POCPSession -VMname $Vmname
        switch ($VMNetAdapter.switchname) 
        {
            "Internal Switch" 
        {
            Check-POCEthernet
        }
            Default {"Connected to wrong Switch: " + $VMNetAdapter.switchname }
        }
    #Check ComputerName    
    Check-POCComputerName
    #Check State after rename and Restart
    # Check-VMState
    #Check If VM is joined to POC domain
    Check-VMDomainJoined
    #Check State after VM joined domain and restart
    #Check-VMState
    #Check Features
    Check-POCFeatures
    }
    }

}
end {
    Get-PSSession | Remove-PSSession
}
}
function Check-VMState {
 "Checking if " + $vmname + " is Running"
    if ($Script:VM.state -ne "running")
    {
        $vmname + " is not Running, Starting"
        try {
        Start-VM $Vmname
        
        do {
            "Checking state of " + $vmname
            $checkstate = (Get-VM $Vmname).Heartbeat
            Start-Sleep -Seconds 2
            "state is " + $checkstate
        } until ($checkstate -eq "OkApplicationsHealthy" )
    }
        catch {$_}
    }
    else {
        $Vmname + " is " + $vm.state
        Start-Sleep -Seconds 5
    }
    
}
function New-POCPSession {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $VMname,
        $Cred = (Get-Credential -Credential administrator),
        $DomainCred = (Get-Credential -credential "Administrator@POC")
    )
    
    "Trying to create PSSession to " + $Vmname + " With Credentials: Host Credentials"
    $Script:PSSession = New-PSSession -VMName $Vmname -Credential $Cred
    if ($Script:PSSession.state -ne "Opened")
    {
        "Trying to create PSSession to " + $Vmname + " With Credentials: Domain Credentials"
        $Script:PSSession = New-PSSession -VMName $Vmname -Credential $DomainCred
        
    }
}
function Check-POCEthernet {
    [CmdletBinding()]
    param (
        $Netadapter = ($VMNetAdapter  | where switchname -eq $_),
        $NetworkOctet = "10.144.143.",
        $Lastoctet = 1 ..  10,
        $Prefix = "20",
        $DefaultGateway = "10.144.143.200",
        $DNS = "10.144.143.1"
    )
    
    begin {
        
    }
    
    process {
                    #Check Ethernet Config

                    $IPArray = foreach ($Octet in $Lastoctet) {
                        $NetworkOctet + $Octet
                    }
                    $UsedIPs = (get-vm) | foreach  {($_ | Get-VMNetworkAdapter | where switchname -eq "Internal Switch").IPAddresses}
                    if ($vmname -ne $DC) 
                    {
                        #Default server IP
                        $IP =  ($IPArray | where -FilterScript { $_ -inotin $UsedIPs})[0]
                    }
                    else {
                        #DC Server IP
                        $ip = $DNS
                    }
                    
                    
                    #lav pssession til maskine og kontrollere
                             "Connecting to $vmname"
                        
                         invoke-command -Session $Script:PSSession -ArgumentList $Netadapter,$IPArray, $IP, $Prefix, $DefaultGateway, $DNS{
                             param ($Netadapter, $IPArray, $IP, $Prefix, $DefaultGateway, $DNS)
                             "Connected Successfully"
                             $currentInterfacealias = Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress
                             if ($currentInterfacealias.InterfaceAlias -ne $Netadapter.SwitchName)
                             {
                                 "Netadapter name is " +  $currentInterfacealias.InterfaceAlias
                                 "Changing to " + $Netadapter.SwitchName
                             Get-NetAdapter | where PermanentAddress -eq $Netadapter.MacAddress | Rename-NetAdapter -NewName $Netadapter.SwitchName 
                             }
                            $EthernetConf = Get-NetIPConfiguration | where InterfaceAlias -eq $Netadapter.switchname
                                if ($EthernetConf.IPv4Address.IPAddress -notin $IPArray -or $Ethernetconf.IPv4DefaultGateway.nexthop -ne $DefaultGateway -or $EthernetConf.dnsserver.ServerAddresses -notcontains $DNS)
                                {
                                    $EthernetConf.InterfaceAlias +" ip is " + $EthernetConf.IPv4Address.IPAddress
                                    "Changing ip to: " + $ip
                                    Remove-NetIPAddress -InterfaceAlias $EthernetConf.InterfaceAlias -IPAddress $EthernetConf.IPv4Address.IPAddress -Confirm:$false
                                    Get-NetRoute -NextHop $Ethernetconf.IPv4DefaultGateway.nexthop | Remove-NetRoute -Confirm:$false
                                    $DefaultGateway
                                    New-NetIPAddress -InterfaceAlias $Netadapter.switchname -IPAddress $IP -DefaultGateway $DefaultGateway -PrefixLength $Prefix  -Confirm:$false
                                    Set-DnsClientServerAddress -InterfaceAlias $Netadapter.switchname -ServerAddresses $DNS
                                }
                                else 
                                {"IP OK"}     
               
                    }
            
    }
    
    end {
        
    }
}
function Check-POCComputerName {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        
    }
    
    process {
                #Check ComputerName
                invoke-command -Session $Script:PSSession -ArgumentList $vmname -ScriptBlock {
                    param ($vmname)
                  
        
                    if ((Get-NetIPConfiguration).computername-ne $vmname)
                    {
                       "Compuername is: " + (Get-NetIPConfiguration).computername
                       "Renaming to: " + $vmname
                       Rename-Computer -NewName $vmname -Confirm:$false
                       Restart-Computer -Force -Wait -For PowerShell -Timeout 300 -Delay 2
                       
                       
                    }
                    else {"Computername is OK: " + (Get-NetIPConfiguration).computername}
                    
                }
    }
    
    end {
        
    }
}
function Check-POCFeatures {
    param (
    )
    if ($vmname -ne $DC) {
        #Default Server Features
        $Features = "RSAT","RSAT-DNS-Server"
    }
    else {
        #DC Features
        $Features = "AD-Domain-Services","DNS","DHCP"
    }
            #Check Features
            "Checking Features on: " + $vmname
            invoke-command -Session $Script:PSSession -ArgumentList (,$Features) -ScriptBlock {
                param ($Features)
                
            foreach ($Feature in $Features) {
                   
                    if ((get-windowsfeature $Feature).installed -ne "true")
                        {
                            $Feature + " Not install, Installing..."
                            install-windowsfeature $Feature
                        }
                        else {
                            $Feature + " Feature Installed"
                        }
             
                 }
            }
}
function Check-POCDomain {
    [CmdletBinding()]
    param (
    )
    begin {
        Get-PSSession | Remove-PSSession
    }
    
   process {
    $script:PSSession = New-PSSession -VMName $DC -Credential $DomainCred
    if (-not $script:PSSession)
    {
        $Pssession = New-PSSession -VMName $DC -Credential administrator
        Invoke-Command -Session $Pssession -ArgumentList $DomainName -ScriptBlock {
            param ($DomainName)
            $getdomain = Get-ADForest
            if (-not $getdomain) 
            {
                "no domain found" 

                "Installing Domain: " + $DomainName

                Import-Module ADDSDeployment
                    Install-ADDSForest `
                    -CreateDnsDelegation:$false `
                    -DatabasePath "C:\Windows\NTDS" `
                    -DomainMode "WinThreshold" `
                    -DomainName $FQDN `
                    -DomainNetbiosName $DomainName `
                    -ForestMode "WinThreshold" `
                    -InstallDns:$true `
                    -LogPath "C:\Windows\NTDS" `
                    -NoRebootOnCompletion:$false `
                    -SysvolPath "C:\Windows\SYSVOL" `
                    -Force:$true
            } 
            else 
            {
                "Domain found: " + (get-adforest).name
            }



        }
    }
    else 
    {
        Invoke-Command -Session $script:PSSession -ArgumentList $DomainName -ScriptBlock {
            param ($DomainName)
            $getdomain = Get-ADForest
            if (-not $getdomain) 
            {
                "no domain found"

            } 
            else 
            {
                "Domain found: " + (get-adforest).name
            }
        }
    }
}
    end {
        Get-PSSession | Remove-PSSession
    }
}
function Check-VMDomainJoined {
    [CmdletBinding()]
    param (
    )
    
    begin {
        
    }
    
    process {
                        #Check ComputerName
                        invoke-command -Session $Script:PSSession -ArgumentList $vmname, $FQDN, $domainname, $DomainCred -ScriptBlock {
                            param ($vmname, $FQDN, $domainname,$DomainCred)
                          
                
                            if ((Get-WmiObject win32_computersystem).domain  -ne $FQDN)
                            {
                               "Computer is in : " + (Get-WmiObject win32_computersystem).domain 
                               "Domain joining : " + $FQDN
                               Add-Computer -ComputerName $vmname -DomainName $domainname  -Credential $DomainCred
                               Restart-Computer -Force -Wait -For PowerShell -Timeout 300 -Delay 2
                            }
                            else {"Domain is OK: " + (Get-WmiObject win32_computersystem).domain}
                            
                        }
        
    }
    
    end {
        
    }
}
function Duplicate-VM {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        # Name of VM you want to Duplicate
        [Parameter()]
        [string]
        $Script:VM,
        # New name for duplicated VM
        [Parameter(Mandatory)]
        [String]
        $NewVMName,
        # VM Path
        [Parameter(Mandatory)]
        [String]
        $VMpath,
        [Parameter()]
        [String]
        $NewVMPath = $VMpath + "\"+ $NewVMName,
        [Parameter()]
        [String]
        $VirtualMachinePath = $NewVMPath + "\Virtual Machines",
        [Parameter()]
        [String]
        $VhdDestinationPath = $NewVMPath + "\Virtual Hard Disks"
    )
    
    begin 
        {
        $Script:VM = (get-vm).Name | Out-GridView -OutputMode Single
        $VmVhd = $vm | Get-VMHardDiskDrive
        $VmVhd.Path
        }
    
    process 
        {
            Write-Debug -Message "debugging"
            if (!(Get-ChildItem $newVMpath -ErrorAction SilentlyContinue).Name -eq $NewVMName)
            {
                New-Item $VhdDestinationPath -ItemType Directory
                Write-Host "Duplicating VM please wait..." -ForegroundColor Yellow 
                $VmVhd.Path | Copy-Item -Destination $VhdDestinationPath
                Get-ChildItem $VhdDestinationPath | Rename-Item -NewName ($NewVMName +".VHDX" )
                $newvhd = Get-ChildItem $VhdDestinationPath
                New-VM -Name $NewVMName -Path  $VMpath  -VHDPath $newvhd.FullName -Generation 2
            }
        else 
             {
                Write-Host $NewVMPath" Exist"
                }
        }
    
    end 
        {
             $VMsName = $null
        }
}
function Push-POCdata {
    [CmdletBinding()]
    param (
        $Vmname = ((get-vm).Name | Out-GridView -OutputMode Single -Title "VM"),
        $item,
        $Destination
       # $Cred = (Get-Credential -Credential administrator),
        #$DomainCred = (Get-Credential -credential "Administrator@POC")
    )
    
    begin {
        New-POCPSession -VMname $Vmname
    }
    
    process {
        "Copying " + $item + " to " + $Destination + " on VM: " + $Vmname
       Copy-Item $item -Destination $Destination -ToSession $PSSession -Recurse
        "Copy Complete"
    }
    
    end {
        $PSSession | Remove-PSSession
    }
}
function Pull-POCData {
    [CmdletBinding()]
    param (
        $Vmname = ((get-vm).Name | Out-GridView -OutputMode Single -Title "VM"),
        $item,
        $Destination
    )
    
    begin {
        New-POCPSession -VMname $Vmname
    }
    
    process {
        "Copying " + $item + " to " + $Destination + " from VM: " + $Vmname
       Copy-Item $item -Destination $Destination -FromSession $PSSession -Recurse
       "Copy Complete"
        
    }
    
    end {
        $PSSession | Remove-PSSession
    }
}
function Remove-POCVM {
    [CmdletBinding()]
    param (
        # Choose VM
        $vm = (Get-VM | Out-GridView -OutputMode Single)
    )
    
    begin {
        if ($vm -eq $null)
        {Write-Error "No vm Picked" -ErrorAction stop}
        $vm = $vm | select *
        $vmname = $vm.Name
        $dc = "dc01"
        New-POCPSession -VMname $dc
        
    }
    
    process 
            {
                
       
        $result = invoke-command -Session $PSSession -ArgumentList $vmname -ScriptBlock {
            param ($vmname)
            try {
                Get-ADComputer -Identity $vmname | Remove-ADObject -Recursive -Confirm -ErrorAction stop
                Remove-DnsServerResourceRecord -ZoneName "poc.local" -RRType "A" -Name $vmname
                return "ok"
            }
            catch {
                return $_
        }
        }

                    
        if ($result -eq "ok")
        {
            Remove-VM -Name $vm.Name -Confirm 
            Remove-Item $vm.Path - -Confirm  
        }
        else {
           Write-Host "Failed to remove computer from AD with:" -ForegroundColor Red
             write-error $result
            }

    }
    
    end {
        
    }
}