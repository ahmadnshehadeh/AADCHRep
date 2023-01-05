
<#

AUTHOR: Tariq

#>

##################
# ///////////////   Refer to C:\Program Files\Microsoft Monitoring Agent\Agent\Troubleshooter
# Check Licenses
##################

#[cmdletbinding()]
# Ref https://certification.comptia.org/it-career-news/post/view/2018/03/09/talk-tech-to-me-powershell-parameters-and-parameter-validation
<#
param(
        [Parameter( Mandatory,HelpMessage='What is the role of this server 'Sync, ADDS, ADFS' ?')]
        [string]$Role="Sync",

        [Parameter( Mandatory=$false)]
        [string]$Par2

      )

#>

# Check running as admin????


    $ComputerName = $env:ComputerName
    $timeLocal = (Get-Date -Format yyyyMMdd_HHmm)
    $timeUTC =  [datetime]::Now.ToUniversalTime().ToString("yyyyMMdd_HHmm")


    $HTMLReport = @()
    $HTMLBody = @()
    $HTMLFile = "$($ComputerName).html"
    $LineBreaker = "<br/>"


#================================================================#
# Checking AAD Heakth agent role(s)
#================================================================#

    $SubHeader = "<h3>AAD Connect Health Role(s)</h3>"
    $HTMLBody += $SubHeader

    $role_Sync = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync"
    $role_ADDS = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADDS"
    $role_ADFS = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADFS"
    
    if($role_Sync) {$HTMLBody += "<h4>SYNC: AAD Connect Server</h4>"}
    if($role_ADDS) {$HTMLBody += "<h4>ADDS: AD Directory Service</h4>"}
    if($role_ADFS) {$HTMLBody += "<h4>ADFS: AD Federation Service</h4>"}
    
    
#================================================================#
# Collect computer system information
#================================================================#
    
    Write-Verbose "Collecting computer system information"

    $SubHeader = "<h3>Computer System Information</h3>"
    $HTMLBody += $SubHeader
    
    try
    {
        $ServerInfo = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction STOP |
            Select-Object Name,Manufacturer,Model,
                        @{Name='Physical Processors';Expression={$_.NumberOfProcessors}},
                        @{Name='Logical Processors';Expression={$_.NumberOfLogicalProcessors}},
                        @{Name='Total Physical Memory (Gb)';Expression={
                            $tpm = $_.TotalPhysicalMemory/1GB;
                            "{0:F0}" -f $tpm
                        }},
                        DnsHostName,Domain
       
       $HTMLBody += $ServerInfo | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker
       
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $HTMLBody += $LineBreaker
    }



#================================================================#
# Collect operating system information
#================================================================#
    
    Write-Verbose "Collecting operating system information"

    $SubHeader = "<h3>Operating System Information</h3>"
    $HTMLBody += $SubHeader
    
    try
    {
        $OSInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction STOP | 
            Select-Object @{Name='Operating System';Expression={$_.Caption}},
                        @{Name='Architecture';Expression={$_.OSArchitecture}},
                        Version,Organization,
                        @{Name='Install Date';Expression={
                            $installdate = [datetime]::ParseExact($_.InstallDate.SubString(0,8),"yyyyMMdd",$null);
                            $installdate.ToShortDateString()
                        }},
                        WindowsDirectory

        $HTMLBody += $OSInfo | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $HTMLBody += $LineBreaker
    }




#================================================================#
# Collect .Net Version information
#================================================================#

    $SubHeader = "<h3>.Net Version</h3>"
    $HTMLBody += $SubHeader
    $dotNetVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"

    $dotNetVersionRep = @()
    $netVerObj = New-Object PSObject
    $netVerObj | Add-Member NoteProperty -Name "Release" -Value $dotNetVersion.Release
    $netVerObj | Add-Member NoteProperty -Name "Version" -Value $dotNetVersion.Version
    $dotNetVersionRep  += $netVerObj

    $HTMLBody += $dotNetVersionRep | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker 


        
#================================================================#
# Collect network interface information
#================================================================#    

    $SubHeader = "<h3>Network Interface Information</h3>"
    $HTMLBody += $SubHeader

    Write-Verbose "Collecting network interface information"

    try
    {
        $nics = @()
        $nicinfo = @(Get-WmiObject Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction STOP | Where {$_.PhysicalAdapter} |
            Select-Object Name,AdapterType,MACAddress,
            @{Name='ConnectionName';Expression={$_.NetConnectionID}},
            @{Name='Enabled';Expression={$_.NetEnabled}},
            @{Name='Speed';Expression={$_.Speed/1000000}})

        $nwinfo = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction STOP |
            Select-Object Description, DHCPServer,  
            @{Name='IpAddress';Expression={$_.IpAddress -join '; '}},  
            @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}},  
            @{Name='DefaultIPgateway';Expression={$_.DefaultIPgateway -join '; '}},  
            @{Name='DNSServerSearchOrder';Expression={$_.DNSServerSearchOrder -join '; '}}

        foreach ($nic in $nicinfo)
        {
            $nicObject = New-Object PSObject
            $nicObject | Add-Member NoteProperty -Name "Connection Name" -Value $nic.connectionname
            $nicObject | Add-Member NoteProperty -Name "Adapter Name" -Value $nic.Name
            $nicObject | Add-Member NoteProperty -Name "Type" -Value $nic.AdapterType
            $nicObject | Add-Member NoteProperty -Name "MAC" -Value $nic.MACAddress
            $nicObject | Add-Member NoteProperty -Name "Enabled" -Value $nic.Enabled
            $nicObject | Add-Member NoteProperty -Name "Speed (Mbps)" -Value $nic.Speed
        
            $ipaddress = ($nwinfo | Where {$_.Description -eq $nic.Name}).IpAddress #-split ";"
            $nicObject | Add-Member NoteProperty -Name "IPAddress" -Value $ipaddress

            $nics += $nicObject
        }

        $HTMLBody += $nics | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $HTMLBody += $LineBreaker
    }


#================================================================#
# Collect Proxy Settings 
#================================================================#		
		
    $SubHeader = "<h3>Proxy Settings: Get-AzureADConnectHealthProxySettings</h3>"
    $HTMLBody += $SubHeader
    Try
    {
        # Set-AzureADConnectHealthProxySettings -NoProxy
        # Set-AzureADConnectHealthProxySettings -HttpsProxyAddress "1.1.1.1:1234"
        # Set-AzureADConnectHealthProxySettings -ImportFromInternetSettings
        # Set-AzureADConnectHealthProxySettings -ImportFromWinHttp

        $AADCHProxy = @()
        $AADCHProxyRep = Get-AzureAdConnectHealthProxySettings

        $proxyObj = New-Object PSObject
        $proxyObj | Add-Member NoteProperty -Name "HttpsProxyAddress" -Value $AADCHProxyRep.HttpsProxyAddress.OriginalString 
        $proxyObj | Add-Member NoteProperty -Name "Host" -Value $AADCHProxyRep.HttpsProxyAddress.Host
        $proxyObj | Add-Member NoteProperty -Name "Port" -Value $AADCHProxyRep.HttpsProxyAddress.Port
        $AADCHProxy  += $proxyObj

        $HTMLBody += $AADCHProxy | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
    }

   
#================================================================#
# Check IE Proxy Settings
#================================================================#

    $SubHeader = "<h3>Proxy Settings: IE</h3>"
    $HTMLBody += $SubHeader
    Try
    {
        $IEProxyReg = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

        $IEProxyRep = @()
        $IEProxyObj = New-Object PSObject
        $IEProxyEnable = "False"
        If($IEProxyReg.ProxyEnable) {$IEProxyEnable = "True"}
        $IEProxyObj | Add-Member NoteProperty -Name "Enabled" -Value $IEProxyEnable
        $IEProxyObj | Add-Member NoteProperty -Name "Proxy Server" -Value ($IEProxyReg.ProxyServer -split ":")[0]
        $IEProxyObj | Add-Member NoteProperty -Name "Port" -Value ($IEProxyReg.ProxyServer -split ":")[1]
        $IEProxyRep += $IEProxyObj

        $HTMLBody += $IEProxyRep | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
    }
    

#================================================================#
# Check netsh Proxy Settings
#================================================================#

    $SubHeader = "<h3>Proxy Settings: netsh</h3>"
    $HTMLBody += $SubHeader
    Try
    {
        # netsh winhttp set proxy server:123
        # netsh winhttp reset proxy 
        $netsh_winhttp = Invoke-Expression "netsh winhttp show proxy"
        $process = $true
        foreach($line in $netsh_winhttp) {if ($line.Contains("no proxy")) {$process = $false}}
        
        $netsh_winhttpRep = @()
        $netshObj = New-Object PSObject
        $netshObj | Add-Member NoteProperty -Name "Proxy Server" -Value ""
        $netshObj | Add-Member NoteProperty -Name "Bypass List" -Value ""
        $netshObj | Add-Member NoteProperty -Name "Port" -Value ""

        if ($process)
        {
            $netshObj = New-Object PSObject
            $netshObj | Add-Member NoteProperty -Name "Proxy Server" -Value ((($netsh_winhttp | select-string -pattern "Proxy Server").ToString().Replace("Proxy Server(s) : ","" ) -split ":")[0] )
            $netshObj | Add-Member NoteProperty -Name "Port" -Value ((($netsh_winhttp | select-string -pattern "Proxy Server").ToString().Replace("Proxy Server(s) : ","" ) -split ":")[1] )
            $netshObj | Add-Member NoteProperty -Name "Bypass List" -Value ( $netsh_winhttp | select-string -pattern "Bypass List").ToString().Replace("Bypass List     :","" )
        }
        $netsh_winhttpRep += $netshObj
        $HTMLBody += $netsh_winhttpRep | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
    }



#================================================================#
# Check machine.config Proxy Settings
#================================================================#

    $SubHeader = "<h3>Proxy Settings: machine.config</h3>"
    $HTMLBody += $SubHeader

    Try
    {
	    [xml]$machineconfig = gc $env:windir\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
        $nodes = ""
        $nodes = $machineconfig.ChildNodes.SelectNodes("/configuration/system.net/defaultProxy/proxy") | Sort -Unique
        $machineConfigProxy = @()
        $MCObj = New-Object PSObject
        $MCObj | Add-Member NoteProperty -Name "UseSystemDefaultm" -Value $nodes.usesystemdefault
        $MCObj | Add-Member NoteProperty -Name "ProxyAddress" -Value $nodes.proxyaddress
        $MCObj | Add-Member NoteProperty -Name "BypassOnLocal" -Value $nodes.bypassonlocal

        $machineConfigProxy += $MCObj
	    $HTMLBody += $machineConfigProxy | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker     

    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
}

#================================================================#
# Check BITSAdmin Proxy Settings
# Ref: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-util-and-getieproxy
#================================================================#

    $SubHeader = "<h3>Proxy Settings: BITSAdmin</h3>"
    $HTMLBody += $SubHeader
    Try
    {
        $bitsadmin_LocalSys = Invoke-Expression "bitsadmin /util /getieproxy localsystem"
        $bitsadmin_NWSvc = Invoke-Expression "bitsadmin /util /getieproxy networkservice"
        $bitsadmin_LSvc = Invoke-Expression "bitsadmin /util /getieproxy localservice"
    
        $BITSAdmin = @()
        $bitsAdminObj = New-Object PSObject
        $bitsAdminObj | Add-Member NoteProperty -Name "Loca System" -Value ($bitsadmin_LocalSys | select-string -pattern "Proxy usage").ToString().Replace("Proxy usage:  ","")
        $bitsAdminObj | Add-Member NoteProperty -Name "Network Service" -Value ($bitsadmin_NWSvc | select-string -pattern "Proxy usage").ToString().Replace("Proxy usage:  ","")
        $bitsAdminObj | Add-Member NoteProperty -Name "Loca Service" -Value ($bitsadmin_LSvc | select-string -pattern "Proxy usage").ToString().Replace("Proxy usage:  ","")
        $BITSAdmin += $bitsAdminObj

        $HTMLBody += $BITSAdmin | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
    }

#================================================================#
# Adding note after proxy settings
#================================================================#
    $HTMLBody += $LineBreaker
    $HTMLBody += "<b>* Empty table means no proxy settings found</b>"



#================================================================#
# Check Encryption Algorithm Settings
#================================================================#

    $SubHeader = "<h3>Encryption algorithms settings in registry</h3>"
    $HTMLBody += $SubHeader
    Try
    {    
        $RSA_SHA512 = "Missing"
        $ECDSA_SHA512 =  "Missing"

	    $reg = Get-ChildItem -Path "hklm:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\"
	    foreach ($r in $reg){
	        #$r.Name
	        $functions = Get-ItemProperty -Path $r.PSPath | select -ExpandProperty Functions
            #$functions
            if ($functions -contains "RSA/SHA512") {$RSA_SHA512 = "Found"}
            if ($functions -contains "ECDSA/SHA512") {$ECDSA_SHA512 = "Found"}
	    } 
        # $RSA_SHA512
        # $ECDSA_SHA512

        $protocolsRep = @()
        $protocolsObj = New-Object PSObject
        $protocolsObj | Add-Member NoteProperty -Name "RSA/SHA512" -Value $RSA_SHA512
        $protocolsObj | Add-Member NoteProperty -Name "ECDSA/SHA512" -Value $ECDSA_SHA512
        $protocolsRep += $protocolsObj

        $HTMLBody += $protocolsRep | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
    }



#================================================================#
# Check TLS 1.2 keys
#================================================================#

    $SubHeader = "<h3>TLS 1.2 registry values</h3>"
    $HTMLBody += $SubHeader

    Function Get-ADSyncToolsTls12RegValue
    {
        [CmdletBinding()]
        Param
        (
            # Registry Path
            [Parameter(Mandatory=$true,
                        Position=0)]
            [string]
            $RegPath,

            # Registry Name
            [Parameter(Mandatory=$true,
                        Position=1)]
            [string]
            $RegName
        )
        $regItem = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Ignore
        $output = "" | select Path,Name,Value
        $output.Path = $RegPath
        $output.Name = $RegName

        If ($regItem -eq $null)
        {
            $output.Value = "Not Found"
        }
        Else
        {
            $output.Value = $regItem.$RegName
        }
        $output
    }

    $regSettings = @()
    $regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'

    $regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'

    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'

    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
    $regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'

    #$regSettings

    $HTMLBody += $regSettings | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker



#================================================================#
# Check Performance Countes
#================================================================#

    $SubHeader = "<h3>Performance Counters</h3>"
    $HTMLBody += $SubHeader

    $perfCRep_sync = @()
    if($role_Sync)
    {   
        $perfCObj = New-Object PSObject
        $perfCObj | Add-Member NoteProperty -Name "Processor" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Processor"))
        $perfCObj | Add-Member NoteProperty -Name "TCPv4" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("TCPv4"))
        $perfCObj | Add-Member NoteProperty -Name "Memory" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Memory"))
        $perfCObj | Add-Member NoteProperty -Name "Process" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Process"))
        $perfCRep_sync += $perfCObj    
    }

    $perfCRep_adds = @()
    if($role_ADDS)
    {   
        $perfCObj = New-Object PSObject
        $perfCObj | Add-Member NoteProperty -Name "Processor" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Processor"))
        $perfCObj | Add-Member NoteProperty -Name "TCPv4" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("TCPv4"))
        $perfCObj | Add-Member NoteProperty -Name "Memory" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Memory"))
        $perfCObj | Add-Member NoteProperty -Name "Process" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Process"))
        $perfCObj | Add-Member NoteProperty -Name "DirectoryServices(NTDS)" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("DirectoryServices(NTDS)"))
        $perfCObj | Add-Member NoteProperty -Name "Security System-Wide Statistics" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Security System-Wide Statistics"))
        $perfCObj | Add-Member NoteProperty -Name "LogicalDisk" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("LogicalDisk"))
        $perfCRep_adds += $perfCObj    
    }

    $HTMLBody += $perfCRep_sync | ConvertTo-Html -Fragment
    $HTMLBody += $perfCRep_adds | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker


########## <#

#================================================================#
# Collect PageFile information
#================================================================#

    $SubHeader = "<h3>PageFile Information</h3>"
    $HTMLBody += $SubHeader

    Write-Verbose "Collecting PageFile information"

    try
    {
        $PageFileInfo = Get-WmiObject Win32_PageFileUsage -ComputerName $ComputerName -ErrorAction STOP |
            Select-Object @{Name='PageFile Name';Expression={$_.Name}},
                        @{Name='Allocated Size (Mb)';Expression={$_.AllocatedBaseSize}}

        $HTMLBody += $PageFileInfo | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $HTMLBody += $LineBreaker
    }



#================================================================#
# Collect logical disk information
#================================================================#


    $SubHeader = "<h3>Logical Disk Information</h3>"
    $HTMLBody += $SubHeader

    Write-Verbose "Collecting logical disk information"

    try
    {
        $diskinfo = Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName -ErrorAction STOP | 
            Select-Object DeviceID,FileSystem,VolumeName,
            @{Expression={$_.Size /1Gb -as [int]};Label="Total Size (GB)"},
            @{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Space (GB)"}

        $HTMLBody += $diskinfo | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $HTMLBody += $LineBreaker
    }




#================================================================#
# Collect software information
#================================================================#


    $SubHeader = "<h3>Software Information</h3>"
    $HTMLBody += $SubHeader
 
    Write-Verbose "Collecting software information"
        
    try
    {
        $software = Get-WmiObject Win32_Product -ComputerName $ComputerName -ErrorAction STOP | Select-Object Vendor,Name,Version | Sort-Object Vendor,Name
        
        $HTMLBody += $software | ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker 
        
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $HTMLBody += $LineBreaker
    }
    
    
    
#================================================================#
# Collect Hotfixes
#================================================================#


    $SubHeader = "<h3>Installed HotFixes</h3>"
    $HTMLBody += $SubHeader
    Try
    {
        $HotFixes = Get-hotfix | select-object -property Description,HotFixID,InstalledBy,InstalledOn | sort InstalledOn -Descending
        $HTMLBody += $HotFixes | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
    }


#================================================================
# Collect services information 
#================================================================#
		
    $SubHeader = "<h3>Computer Services Information</h3>"
    $HTMLBody += $SubHeader
		
    Write-Verbose "Collecting services information"

    try
    {
        $services = Get-WmiObject Win32_Service -ComputerName $ComputerName -ErrorAction STOP  | Select-Object Name,StartName,State,StartMode | Sort-Object Name

        $HTMLBody += $services | ConvertTo-Html -Fragment
        # $HTMLBody += $LineBreaker 
        
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $HTMLBody += $LineBreaker
    }



#================================================================#
# Run Connectivity test
#================================================================#
    
    $SubHeader = "<h3>Test-AzureADConnectHealthConnectivity</h3>"
    $HTMLBody += $SubHeader
    
    $testResults_Sync = ""
    if($role_Sync)
    {
        $testResults_Sync = Test-AzureADConnectHealthConnectivity -Role sync
    }
    
    $testResults_ADDS = ""
    if($role_ADDS)
    {
        $testResults_ADDS = Test-AzureADConnectHealthConnectivity -Role adds
    }

    $testResults_ADFS = ""
    if($role_ADFS)
    {
        $testResults_ADFS = Test-AzureADConnectHealthConnectivity -Role adfs
    }


    if($testResults_Sync) 
    { 
        
        $HTML_rep = ""
        $HTML_rep += "<Table style='font-size:13px; font-family:Tahoma; border-style:solid #4472C4 1.5pt; white-space: pre;'>"
            $HTML_rep += "<tr><td valign='top' style='background:#DEEAF6'>"
                    $HTML_rep += "<b><h4>==== Testing for Sync Role ====</h4></b>"
            $HTML_rep += "</td></tr>"

            $HTML_rep += "<tr style='background:#17202A; font-size:13px; font-family:Consolas,Tahoma; color:Lime'>"
                $HTML_rep += "<td valign='top'>"
                    #$HTML_rep += "==========DATA=========="
                    Foreach ($line in $testResults_Sync) { $HTML_rep += $line + $LineBreaker }
                $HTML_rep += "</td>"
            $HTML_rep += "</tr>"
        $HTML_rep += "</table>"
        $HTML_rep += $LineBreaker

        $HTMLBody += $HTML_rep

        #$HTMLBody += "<h4>==== Testing for Sync Role ====</h4>"
        #Foreach ($line in $testResults_Sync) { $HTMLReport+= "<h4>Test-AzureADConnectHealthConnectivity -Role Sync</h4>"; $HTMLBody += $line + $LineBreaker }
    }


    if($testResults_ADDS) 
    { 
         $HTML_rep = ""
        $HTML_rep += "<Table style='font-size:13px; font-family:Tahoma; border-style:solid #4472C4 1.5pt; white-space: pre;'>"
            $HTML_rep += "<tr><td valign='top' style='background:#DEEAF6'>"
                    $HTML_rep += "<b><h4>==== Testing for ADDS Role ====</h4></b>"
            $HTML_rep += "</td></tr>"

            $HTML_rep += "<tr style='background:#17202A; font-size:13px; font-family:Consolas,Tahoma; color:Lime'>"
                $HTML_rep += "<td valign='top' '>"
                    #$HTML_rep += "==========DATA=========="
                    Foreach ($line in $testResults_ADDS) { $HTML_rep += $line + $LineBreaker }
                $HTML_rep += "</td>"
            $HTML_rep += "</tr>"
        $HTML_rep += "</table>"
        $HTML_rep += $LineBreaker

        $HTMLBody += $HTML_rep

        #$HTMLBody += "<h4>==== Testing for ADDS Role ====</h4>"
        #Foreach ($line in $testResults_ADDS) { $HTMLReport+= "<h4>Test-AzureADConnectHealthConnectivity -Role ADDS</h4>"; $HTMLBody += $line + $LineBreaker }
    }

    if($testResults_ADFS) 
    {
        $HTML_rep = ""
        $HTML_rep += "<Table style='font-size:13px; font-family:Tahoma; border-style:solid #4472C4 1.5pt; white-space: pre;'>"
            $HTML_rep += "<tr><td valign='top' style='background:#DEEAF6'>"
                    $HTML_rep += "<b><h4>==== Testing for ADFS Role ====</h4></b>"
            $HTML_rep += "</td></tr>"

            $HTML_rep += "<tr style='background:#17202A; font-size:13px; font-family:Consolas,Tahoma; color:Lime'>"
                $HTML_rep += "<td valign='top'>"
                    #$HTML_rep += "==========DATA=========="
                    Foreach ($line in $testResults_ADFS) { $HTML_rep += $line + $LineBreaker }
                $HTML_rep += "</td>"
            $HTML_rep += "</tr>"
        $HTML_rep += "</table>"
        $HTML_rep += $LineBreaker

        $HTMLBody += $HTML_rep

        #$HTMLBody += "<h4>==== Testing for ADFS Role ====</h4>"
        #Foreach ($line in $testResults_ADFS) { $HTMLReport+= "<h4>Test-AzureADConnectHealthConnectivity -Role ADFS</h4>"; $HTMLBody += $line + $LineBreaker } 
    }
  
    #($testResults_Sync | Out-String).ToString() |  ConvertTo-Html -Fragment
    # $HTMLBody += $LineBreaker 


    

#================================================================#
# Generate the HTML report and output to file
#================================================================#
	
    Write-Verbose "Producing HTML report"
    
    $ReporTime = Get-Date

    $ReportTimeUTC =  [datetime]::Now.ToUniversalTime() #.ToString("yyyyMMdd_HHmm")

    #Common HTML head and styles
	$htmlhead="<html>
				<style>
				    BODY{font-family: Consolas,Arial; font-size: 10pt;}
				    H1{font-size: 20px;}
				    H2{font-size: 18px;}
				    H3{font-size: 14px;font-weight: bold; color:blue}
                    H4{font-size: 12px; }
				    TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				    TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
				    TD{border: 1px solid black; padding: 5px; }
				    td.pass{background: #7FFF00;}
				    td.warn{background: #FFE600;}
				    td.fail{background: #FF0000; color: #ffffff;}
				    td.info{background: #85D4FF;}
                    p {color: red;}
				</style>
				<body>
				<h1>Server Info: $ComputerName</h1>
				<h3>Generated Local: $reportime</h3>
                <h3>Generated (UTC): $ReportTimeUTC</h3>"

    $htmltail = "</body>
			</html>"

    $HTMLReport = $htmlhead + $HTMLBody + $htmltail

    $HTMLReport | Out-File $HTMLFile -Encoding Utf8




##################################################################
##################################################################
#================================================================#
#      Following part are for collecting ideas
#      Script code stops running after this line.
#================================================================#
##################################################################
##################################################################


break

#================================================================#
# Collect agent log files
#================================================================#

#== Temp folder where files will be colected
    $Folder_name = "C:\temp"

#== Check files in current logged in user Temp files
    $Path = "$env:USERPROFILE\AppData\Local\Temp"
    $Files = ""
    $Files = Get-ChildItem -Path "$Path\*" -Include "ad*", "*Health_agent*" 
    $Folders = Get-ChildItem -Path $Path\* | where psiscontainer
    foreach($f in $Folders)
    {
        #$f
       $Files += Get-ChildItem -Path $f\* -Include "ad*", "*Health_agent*" 
    }

    #$Files | Compress-Archive -DestinationPath "C:\temp\$ArchiveName.zip" -Force

#== Search in other possible folders
    $TemporaryInstallationLogPath  = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync").TemporaryInstallationLogPath 
    $PathFromReg = Split-Path $TemporaryInstallationLogPath  -Parent
    If ($path -ne $PathFromReg) {
        $Folders = Get-ChildItem -Path $Path | where psiscontainer
        foreach($f in $Folders)
        {
            #$f
           $Files += Get-ChildItem -Path $f\* -Include "ad*", "*Health_agent*" 
        }
    }

#== Generate Archive file
    $ArchiveName = $env:ComputerName+"_AgentLogs_"+$(Get-Date -Format yyyyMMdd_HHmm)
    $ArchiveNameUTC = $env:ComputerName + "_AgentLogs_" + [datetime]::Now.ToUniversalTime().ToString("yyyyMMdd_HHmm")

#== Un-comment following line to collect and compress the files
    #$Files | Compress-Archive -DestinationPath "$Folder_name\$ArchiveName.zip" -Force
    # Add in HTML Report details about Files (names) and the Archive File path



#================================================================#
# Things to Collect to troubleshoot AADC Health issues
#
#
#
<#=========================================================#>
# Completed items
<#---------------------------------------------------------#>

    #Server detaisl, IP name, HW
    #-----------> Done

    # Proxy settings from all , HA, IE, Netsh
    #-----------> Done
    # >> From  machine.config, get-azureadHAproxy, bitsadmin
        Get-AzureAdConnectHealthProxySettings
    #-----------> Done

    # Winver
    #-----------> Done

    # Net version
    #-----------> Done

    #Encryption Algorithm
    #-----------> Done

    #TLS & SSL
    #-----------> Done

    #Perfcounters
    #-----------> Done

    #Installed updates KB
    #-----------> Done


<#---------------------------------------------------------#>
# /end of Completed items
<#=========================================================#>


# Proxy from registration logs
# if no proxy use PsExec to edit monitor.config insight...


#agent Certificates

#Run IE as system 
 #        psexec -s -i "c:\Program Files\Internet Explorer\iexplore.exe"


# chek Memeory limit / OneNote "Health Agent Memory limit"

#MSInfo




Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\ProductOptions" 
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent"

Test-AzureADConnectHealthConnectivity -Role sync


break

#################
# Testing logs
""

# Get Installation Path
mybreak
Write-Host "Checking Health Agent installation path..." -ForegroundColor Yellow
$role="Sync"
Switch ($Role)
{
    Sync
    {
        Write-Host "Selected role is: " -ForegroundColor Green -NoNewline
        Write-Host $Role -ForegroundColor Yellow
    }
}
$TemporaryInstallationLogPath = Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync -Name TemporaryInstallationLogPath
$installationPath = Split-Path  $TemporaryInstallationLogPath.TemporaryInstallationLogPath
Write-Host "AD Connect Agent installation path: " -ForegroundColor Green -NoNewline
Write-Host $installationPath -ForegroundColor Yellow

$Files = Get-ChildItem -Path $installationPath -Include "ad*", "*Health_agent*"
$ArchiveName = $env:ComputerName+"_"+$(get-date -Format yyyyMMdd_hhmm)
$Files | Compress-Archive -DestinationPath C:\temp\test.zip -Force



#get-childitem -path HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ -recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*Netwrix*"}
#get-childitem -path HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync -recurse # | Where-Object {$_.Name -like "*installation*"}



# Get List of all domain controllers
Get-ADComputer -Filter 'primarygroupid -eq "516"' -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address | Sort-Object -Property Operatingsystem |
Select-Object -Property Name,Operatingsystem,OperatingSystemVersion,IPv4Address


#start netsh trace
    #Show message Do you want to collect NW Trace? 
    $Folder_name = "C:\temp"
    $netTraceFile = $Role + "_" + $ComputerName + "_netTrace_" + $timeUTC
    $netTraceFile = $Folder_name + "\" + $netTraceFile + ".etl"
    #Warning about collected MaxSize
    Invoke-Expression "netsh trace start traceFile=$netTraceFile capture=yes maxsize=10240"
    Sleep -Seconds 4

    Invoke-Expression "ipconfig /flushdns"
    Sleep -Seconds 1

    Invoke-Expression "nbtstat -RR"

    #Test / Register / Restart Service / ,,,,
    #Test connectivity
    # use Akos_healthAgentEndPoints.ps1

    #Show message to repro the issue
    #Invoke-Expression "netsh trace stop"
