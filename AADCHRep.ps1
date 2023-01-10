<#

.SYNOPSIS
    AADCHRep V1.0 PowerShell script.

.DESCRIPTION
    Azure AD Connect Health tool checks the requirments for Azure AD Connect Health agent and collects agent to help identifying and fixing most of the common AAD Connect Health agent issues.

.AUTHOR:
    Tariq Jaber

.EXAMPLE
    .\AADCHRep.ps1

#>
    $global:ComputerName = $env:ComputerName
    $global:timeLocal = (Get-Date -Format yyyyMMdd_HHmm)
    $global:timeUTC =  [datetime]::Now.ToUniversalTime().ToString("yyyyMMdd_HHmm")
    $outputColor = "Green"
    $global:TenantID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent").TenantId

    $global:role_Sync = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync"
    $global:role_ADDS = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADDS"
    $global:role_ADFS = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADFS"

#== Temp folder where files will be colected
    $global:Folder_name = "C:\temp"
    $global:savedLogsPath =""

    $HTMLReport = @()
    $global:HTMLBody = @()
    $global:HTMLFileUTC = $global:ComputerName + "_RequirementsCheck_" + [datetime]::Now.ToUniversalTime().ToString("yyyyMMdd_HHmmss")
    $global:HTMLFile = "$global:Folder_name\$global:HTMLFileUTC" + "_UTC.html"
    

    $global:LineBreaker = "<br/>"

#================================================================#
# Checking AAD Heakth agent role(s)
#================================================================#
Function AADCHRole {
    Write-Host 'Checking AAD Heakth agent role(s)' -ForegroundColor $outputColor
    $SubHeader = "<h3>AAD Connect Health Role(s)</h3>"
    $global:HTMLBody += $SubHeader

    $global:role_Sync = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync"
    $global:role_ADDS = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADDS"
    $global:role_ADFS = Test-Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADFS"
    
    $global:HTMLBody += "<h4>Following role(s) detected:</h4>"
    if($global:role_Sync) {$global:HTMLBody += "<b>SYNC: AAD Connect Server</b><br/>"}
    if($global:role_ADDS) {$global:HTMLBody += "<b>ADDS: AD Directory Service</b><br/>"}
    if($global:role_ADFS) {$global:HTMLBody += "<b>ADFS: AD Federation Service</b><br/>"}
    
    $global:HTMLBody += "<h4>TenantID: $global:TenantID </h4>"

}    


#================================================================#
# Collect Agent Details 
#================================================================#
Function agentDetails{
    Write-Host 'Collecting agent details' -ForegroundColor $outputColor


    $agentDetails=@()
    if($global:role_Sync) {$agentDetails += Get-Item -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync"}
    if($global:role_ADDS) {$agentDetails += Get-Item -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADDS"}
    if($global:role_ADFS) {$agentDetails += Get-Item -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADFS"}
    
    foreach($agent in $agentDetails)
    {
        $Role = $agent.Name | Split-Path -Leaf
        $HTML_rep = ""
        $HTML_rep += "<Table style='font-size:13px; font-family:Tahoma; border-style:solid #4472C4 1.5pt; white-space: pre;'>"
            $HTML_rep += "<tr><td valign='top' style='background:#DEEAF6' colspan=2>"
                    $HTML_rep += "<b><h4> -=-=-=( General Agent details from Registry: $Role  )=-=-=- </h4></b>"
            $HTML_rep += "</td></tr>"
            $HTML_rep += "<tr style=' font-size:13px; font-family:Consolas,Tahoma;'>"

        Foreach($ItemProperty in $agent.GetValueNames())
        {
                $HTML_rep += "<td valign='top'>" + $ItemProperty +"</td>"
                $HTML_rep += "<td valign='top'>" + $agent.GetValue($ItemProperty) + "</td></tr>"
        }
            $HTML_rep += "</tr>"
        $HTML_rep += "</table>"
        $global:HTMLBody += $HTML_rep
        $global:HTMLBody += $LineBreaker
    }

}
    
#================================================================#
# Collect computer system information
#================================================================#
Function CSInfo {
    Write-Host 'Collecting computer system information' -ForegroundColor $outputColor

    $SubHeader = "<h3>Computer System Information</h3>"
    $global:HTMLBody += $SubHeader
    
    try
    {
        $ServerInfo = Get-WmiObject Win32_ComputerSystem -ComputerName $global:ComputerName -ErrorAction STOP |
            Select-Object Name,Manufacturer,Model,
                        @{Name='Physical Processors';Expression={$_.NumberOfProcessors}},
                        @{Name='Logical Processors';Expression={$_.NumberOfLogicalProcessors}},
                        @{Name='Total Physical Memory (Gb)';Expression={
                            $tpm = $_.TotalPhysicalMemory/1GB;
                            "{0:F0}" -f $tpm
                        }},
                        DnsHostName,Domain
       
       $global:HTMLBody += $ServerInfo | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker
       
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $global:HTMLBody += $global:LineBreaker
    }
}

#================================================================#
# Collect operating system information
#================================================================#
Function OSInfo {    
    Write-Host 'Collecting operating system information' -ForegroundColor $outputColor

    $SubHeader = "<h3>Operating System Information</h3>"
    $global:HTMLBody += $SubHeader
    
    try
    {
        $OSInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $global:ComputerName -ErrorAction STOP | 
            Select-Object @{Name='Operating System';Expression={$_.Caption}},
                        @{Name='Architecture';Expression={$_.OSArchitecture}},
                        Version,Organization,
                        @{Name='Install Date';Expression={
                            $installdate = [datetime]::ParseExact($_.InstallDate.SubString(0,8),"yyyyMMdd",$null);
                            $installdate.ToShortDateString()
                        }},
                        WindowsDirectory

        $global:HTMLBody += $OSInfo | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $global:HTMLBody += $global:LineBreaker
    }
}

#================================================================#
# Collect .Net Version information
#================================================================#
Function dotNetVersion{
    Write-Host 'Checking .Net Version' -ForegroundColor $outputColor
    $SubHeader = "<h3>.Net Version</h3>"
    $global:HTMLBody += $SubHeader
    $dotNetVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"

    $dotNetVersionRep = @()
    $netVerObj = New-Object PSObject
    $netVerObj | Add-Member NoteProperty -Name "Release" -Value $dotNetVersion.Release
    $netVerObj | Add-Member NoteProperty -Name "Version" -Value $dotNetVersion.Version
    $dotNetVersionRep  += $netVerObj

    $global:HTMLBody += $dotNetVersionRep | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker 
}

#================================================================#
# Collect network interface information
#================================================================#    
Function NICInfo{
    Write-Host 'Collecting network interface information' -ForegroundColor $outputColor     
    $SubHeader = "<h3>Network Interface Information</h3>"
    $global:HTMLBody += $SubHeader

    Write-Verbose "Collecting network interface information"

    try
    {
        $nics = @()
        $nicinfo = @(Get-WmiObject Win32_NetworkAdapter -ComputerName $global:ComputerName -ErrorAction STOP | Where {$_.PhysicalAdapter} |
            Select-Object Name,AdapterType,MACAddress,
            @{Name='ConnectionName';Expression={$_.NetConnectionID}},
            @{Name='Enabled';Expression={$_.NetEnabled}},
            @{Name='Speed';Expression={$_.Speed/1000000}})

        $nwinfo = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $global:ComputerName -ErrorAction STOP |
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

        $global:HTMLBody += $nics | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $global:HTMLBody += $global:LineBreaker
    }
}

#================================================================#
# Collect AADCH Proxy Settings 
#================================================================#		
Function Proxy_AADCH{
    Write-Host 'Checking Proxy settings: Get-AzureADConnectHealthProxySettings' -ForegroundColor $outputColor
    $SubHeader = "<h3>Proxy Settings: Get-AzureADConnectHealthProxySettings</h3>"
    $global:HTMLBody += $SubHeader
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

        $global:HTMLBody += $AADCHProxy | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
    }
}
   
#================================================================#
# Check IE Proxy Settings
#================================================================#
Function Proxy_IE{
    Write-Host 'Checking Proxy settings: IE Settings' -ForegroundColor $outputColor
    $SubHeader = "<h3>Proxy Settings: IE</h3>"
    $global:HTMLBody += $SubHeader
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

        $global:HTMLBody += $IEProxyRep | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
    }
}

#================================================================#
# Check netsh Proxy Settings
#================================================================#
Function Proxy_netsh{
    Write-Host 'Checking Proxy settings: netsh Settings' -ForegroundColor $outputColor
    $SubHeader = "<h3>Proxy Settings: netsh</h3>"
    $global:HTMLBody += $SubHeader
    Try
    {
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
        $global:HTMLBody += $netsh_winhttpRep | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
    }
}


#================================================================#
# Check machine.config Proxy Settings
#================================================================#
Function Proxy_machineConfig{
    Write-Host 'Checking Proxy settings: machine.config file' -ForegroundColor $outputColor
    $SubHeader = "<h3>Proxy Settings: machine.config</h3>"
    $global:HTMLBody += $SubHeader

    Try
    {
	    [xml]$machineconfig = gc $env:windir\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
        $nodes = ""
        $nodes = $machineconfig.ChildNodes.SelectNodes("/configuration/system.net/defaultProxy/proxy") | Sort -Unique
        $machineConfigProxy = @()
        $MCObj = New-Object PSObject
        $MCObj | Add-Member NoteProperty -Name "UseSystemDefault" -Value $nodes.usesystemdefault
        $MCObj | Add-Member NoteProperty -Name "ProxyAddress" -Value $nodes.proxyaddress
        $MCObj | Add-Member NoteProperty -Name "BypassOnLocal" -Value $nodes.bypassonlocal

        $machineConfigProxy += $MCObj
	    $global:HTMLBody += $machineConfigProxy | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker     

    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
}
}

#================================================================#
# Check BITSAdmin Proxy Settings
# Ref: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-util-and-getieproxy
#================================================================#
Function Proxy_BITSAdmin{
    Write-Host 'Checking Proxy settings: bitsadmin Settings' -ForegroundColor $outputColor
    $SubHeader = "<h3>Proxy Settings: BITSAdmin</h3>"
    $global:HTMLBody += $SubHeader
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

        $global:HTMLBody += $BITSAdmin | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
    }
}

#================================================================#
# Adding note after proxy settings
#================================================================#
Function Proxy_Notes{
    $global:HTMLBody += $global:LineBreaker
    $global:HTMLBody += "<b>* Empty table(s) means no proxy settings found</b>"
    
    $global:HTMLBody += $global:LineBreaker
    $global:HTMLBody += "<b>* Authenticated proxies (using HTTPBasic) are not supported </b>"
    $global:HTMLBody += "<a href='https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-health-agent-install#configure-azure-ad-connect-health-agents-to-use-http-proxy'>"
    $global:HTMLBody += "<b>(Link)</b></a>"

    $global:HTMLBody += $global:LineBreaker
    $global:HTMLBody += "<b>** Check with your Network Security team if inline/transparent proxy is used in your environment</b>"
    $global:HTMLBody += $global:LineBreaker
}

#================================================================#
# Check Encryption Algorithm Settings
#================================================================#
Function encryptionAlgorithm{
    Write-Host 'Checking Registry keys for: Encryption Algorithm ' -ForegroundColor $outputColor
    $SubHeader = "<h3>Encryption algorithms settings in registry</h3>"
    $global:HTMLBody += $SubHeader
    Try
    {    
        $RSA_SHA512 = "Missing"
        $ECDSA_SHA512 =  "Missing"

	    $reg = Get-ChildItem -Path "hklm:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\"
	    foreach ($r in $reg){
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

        $global:HTMLBody += $protocolsRep | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
    }
}


#================================================================#
# Check TLS 1.2 keys
# https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-tls-enforcement#powershell-script-to-check-tls-12
#================================================================#
Function Get-ADSyncToolsTls12RegValue {
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
Function TLS12{
    Write-Host 'Checking Registry keys for: TLS 1.2 settings' -ForegroundColor $outputColor
    $SubHeader = "<h3>TLS 1.2 registry values</h3>"
    $global:HTMLBody += $SubHeader


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

    
    $global:HTMLBody += $regSettings | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker
}

#================================================================#
# Check required CA certificate as documented on
# https://learn.microsoft.com/en-us/azure/security/fundamentals/tls-certificate-changes#what-changed
#================================================================#
Function rootCA {
#    DigiCert Global Root G2                           df3c24f9bfd666761b268073fe06d1cc8d4f82a4
#    DigiCert Global Root CA	                       a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436
#    Baltimore CyberTrust Root	                       d4de20d05e66fc53fe1a50882c78db2852cae474
#    D-TRUST Root Class 3 CA 2 2009	                   58e8abb0361533fb80f79b1b6d29d3ff8d5f00f0
#    Microsoft RSA Root Certificate Authority 2017	   73a5e64a3bff8316ff0edccc618a906e4eae4d74
#    Microsoft ECC Root Certificate Authority 2017	   999a64c37ff47d9fab95f14769891460eec4c3c5
#
#
Write-Host 'Checking required Root Certificate Autorities certificates' -ForegroundColor $outputColor
    $SubHeader = "<h3>Required Root CA certificates</h3>"
    $global:HTMLBody += $SubHeader

    #$global:HTMLBody += $global:LineBreaker
    $global:HTMLBody += "<b>Following is the list of required Root CA certificates thumbprints:</b>"


    $requiredRootCAs = @(
    "df3c24f9bfd666761b268073fe06d1cc8d4f82a4",
    "a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436",
    "d4de20d05e66fc53fe1a50882c78db2852cae474",
    "58e8abb0361533fb80f79b1b6d29d3ff8d5f00f0",
    "73a5e64a3bff8316ff0edccc618a906e4eae4d74",
    "999a64c37ff47d9fab95f14769891460eec4c3c5"
    )

     
    $requiredRCARep = @()
    foreach($rRCA in $requiredRootCAs)
    {   
        $requiredRCAObj = New-Object PSObject
        $requiredRCAObj | Add-Member NoteProperty -Name "Thumbprint" -Value $rRCA
        $requiredRCARep += $requiredRCAObj
    }

    $global:HTMLBody += $requiredRCARep | ConvertTo-Html -Fragment

    # Extract hashes of "Trusted Root Certification Authorities" for the computer.
    $computertrusted =@()
    dir cert:\localmachine\root | foreach { $computertrusted += $_.Thumbprint.ToString()} 
    $missingRootCA = Foreach ($ca in $requiredRootCAs) { if (!$computertrusted.Contains( $ca.ToUpper() ) ) { $ca } } 
    
    $missingRCARep = @()
    foreach($mRCA in $missingRootCA)
    {   
        $missingRCAObj = New-Object PSObject
        $missingRCAObj | Add-Member NoteProperty -Name "Thumbprint" -Value $mRCA
        $missingRCARep += $missingRCAObj
    }

    If($missingRCARep.Count)
    {
        $global:HTMLBody += $global:LineBreaker 
        $global:HTMLBody += "<b>Following Root CA certificate(s) thumbprints is/are missing </b>"
        $global:HTMLBody += $missingRCARep | ConvertTo-Html -Fragment
    }
    else {
        $global:HTMLBody += $global:LineBreaker 
        $global:HTMLBody += "<b>There are no missing Root CA certificate </b>"
        
    }

    $global:HTMLBody += $global:LineBreaker 
    $global:HTMLBody += "<a href='https://learn.microsoft.com/en-us/azure/security/fundamentals/tls-certificate-changes#what-changed'>Ref: Azure TLS certificate changes</a>"
    $global:HTMLBody += $global:LineBreaker 
    # $global:HTMLBody += $global:LineBreaker 
}


#================================================================#
# Check Performance Counters
#================================================================#
Function PerfCounters{
    Write-Host 'Checking performance counters' -ForegroundColor $outputColor
    $SubHeader = "<h3>Performance Counters</h3>"
    $global:HTMLBody += $SubHeader

    $perfCRep_sync = @()
    if($global:role_Sync)
    {   
        $perfCObj = New-Object PSObject
        $perfCObj | Add-Member NoteProperty -Name "Processor" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Processor"))
        $perfCObj | Add-Member NoteProperty -Name "TCPv4" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("TCPv4"))
        $perfCObj | Add-Member NoteProperty -Name "Memory" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Memory"))
        $perfCObj | Add-Member NoteProperty -Name "Process" -Value ([System.Diagnostics.PerformanceCounterCategory]::Exists("Process"))
        $perfCRep_sync += $perfCObj    
    }

    $perfCRep_adds = @()
    if($global:role_ADDS)
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

    $global:HTMLBody += $perfCRep_sync | ConvertTo-Html -Fragment
    $global:HTMLBody += $perfCRep_adds | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker

}


#================================================================#
# Collect PageFile information
#================================================================#
Function pageFiles{
    Write-Host 'More info: Checking Page files' -ForegroundColor $outputColor
    $SubHeader = "<h3>PageFile Information</h3>"
    $global:HTMLBody += $SubHeader

    Write-Verbose "Collecting PageFile information"

    try
    {
        $PageFileInfo = Get-WmiObject Win32_PageFileUsage -ComputerName $global:ComputerName -ErrorAction STOP |
            Select-Object @{Name='PageFile Name';Expression={$_.Name}},
                        @{Name='Allocated Size (Mb)';Expression={$_.AllocatedBaseSize}}

        $global:HTMLBody += $PageFileInfo | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $global:HTMLBody += $global:LineBreaker
    }
}


#================================================================#
# Collect logical disk information
#================================================================#
Function logicalDisk{
    Write-Host 'More info: Checking Logical Disks' -ForegroundColor $outputColor
    $SubHeader = "<h3>Logical Disk Information</h3>"
    $global:HTMLBody += $SubHeader

    Write-Verbose "Collecting logical disk information"

    try
    {
        $diskinfo = Get-WmiObject Win32_LogicalDisk -ComputerName $global:ComputerName -ErrorAction STOP | 
            Select-Object DeviceID,FileSystem,VolumeName,
            @{Expression={$_.Size /1Gb -as [int]};Label="Total Size (GB)"},
            @{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Space (GB)"}

        $global:HTMLBody += $diskinfo | ConvertTo-Html -Fragment
    # $global:HTMLBody += $global:LineBreaker
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $global:HTMLBody += $global:LineBreaker
    }
}


#================================================================#
# Collect software information
#================================================================#
Function softwareInfo{
    Write-Host 'Checking installed softwares' -ForegroundColor $outputColor
    $SubHeader = "<h3>Software Information</h3>"
    $global:HTMLBody += $SubHeader
 
    Write-Verbose "Collecting software information"
        
    try
    {
        $software = Get-WmiObject Win32_Product -ComputerName $global:ComputerName -ErrorAction STOP | Select-Object Vendor,Name,Version | Sort-Object Vendor,Name
        
        $global:HTMLBody += $software | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
        
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    # $global:HTMLBody += $global:LineBreaker
    }
}
    
#================================================================#
# Collect Hotfixes
#================================================================#
Function hotfixes{
Write-Host 'Checking installed Hotfixes' -ForegroundColor $outputColor
    $SubHeader = "<h3>Installed HotFixes</h3>"
    $global:HTMLBody += $SubHeader
    Try
    {
        $HotFixes = Get-hotfix | select-object -property Description,HotFixID,InstalledBy,InstalledOn | sort InstalledOn -Descending
        $global:HTMLBody += $HotFixes | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
    }
}

#================================================================
# Collect services information 
#================================================================#
Function servicesInfo{	
Write-Host 'Checking installed services' -ForegroundColor $outputColor	
    $SubHeader = "<h3>Computer Services Information</h3>"
    $global:HTMLBody += $SubHeader
		
    Write-Verbose "Collecting services information"

    try
    {
        $services = Get-WmiObject Win32_Service -ComputerName $global:ComputerName -ErrorAction STOP  | Select-Object Name,StartName,State,StartMode | Sort-Object Name

        $global:HTMLBody += $services | ConvertTo-Html -Fragment
        # $global:HTMLBody += $global:LineBreaker 
        
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
        # $global:HTMLBody += $global:LineBreaker
    }
}

#================================================================#
# Run Connectivity test
#================================================================#
Function connectivityTest{    
    Write-Host 'Running Connectivity Test' -ForegroundColor $outputColor
    $SubHeader = "<h3>Test-AzureADConnectHealthConnectivity</h3>"
    $global:HTMLBody += $SubHeader
    
    $testResults_Sync = ""
    if($global:role_Sync)
    {
        $testResults_Sync = Test-AzureADConnectHealthConnectivity -Role sync
    }
    
    $testResults_ADDS = ""
    if($global:role_ADDS)
    {
        $testResults_ADDS = Test-AzureADConnectHealthConnectivity -Role adds
    }

    $testResults_ADFS = ""
    if($global:role_ADFS)
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
                    Foreach ($line in $testResults_Sync) { $HTML_rep += $line + $global:LineBreaker }
                $HTML_rep += "</td>"
            $HTML_rep += "</tr>"
        $HTML_rep += "</table>"
        $HTML_rep += $global:LineBreaker

        $global:HTMLBody += $HTML_rep

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
                    Foreach ($line in $testResults_ADDS) { $HTML_rep += $line + $global:LineBreaker }
                $HTML_rep += "</td>"
            $HTML_rep += "</tr>"
        $HTML_rep += "</table>"
        $HTML_rep += $global:LineBreaker

        $global:HTMLBody += $HTML_rep

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
                    Foreach ($line in $testResults_ADFS) { $HTML_rep += $line + $global:LineBreaker }
                $HTML_rep += "</td>"
            $HTML_rep += "</tr>"
        $HTML_rep += "</table>"
        $HTML_rep += $global:LineBreaker

        $global:HTMLBody += $HTML_rep

    }
}

#================================================================#
# Collect agent log files
#================================================================#
Function collectLogs{
Write-Host 'Collecting AAD Connect Health agent log files' -ForegroundColor $outputColor
    $SubHeader = "<h3>Collecting agent log files - Required for troubleshooting</h3>"
    $global:HTMLBody += $SubHeader

    Try {
    #== Check files in current logged in user Temp files
        $Path = "$env:USERPROFILE\AppData\Local\Temp"
        $Files = ""
        $Files = Get-ChildItem -Path "$Path\*" -Include "ad*", "*Health_agent*" , "Str"
        $Folders = Get-ChildItem -Path $Path\* | where psiscontainer
        foreach($f in $Folders)
        {
           $Files += Get-ChildItem -Path $f\* -Include "ad*", "*Health_agent*" 
        }

    #== Search in other possible folders
        $TemporaryInstallationLogPath  = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\Sync").TemporaryInstallationLogPath 
        $PathFromReg = Split-Path $TemporaryInstallationLogPath  -Parent
        If ($path -ne $PathFromReg) {
            $Folders = Get-ChildItem -Path $PathFromReg | where psiscontainer
            foreach($f in $Folders)
            {
               $Files += Get-ChildItem -Path $f\* -Include "ad*", "*Health_agent*" 
            }
        }

        if ($Files.Count) 
        {
        #== Generate Archive file
            $ArchiveName = $env:ComputerName+"_AgentLogs_"+$(Get-Date -Format yyyyMMdd_HHmmss)
            $ArchiveNameUTC = $env:ComputerName + "_AgentLogs_" + [datetime]::Now.ToUniversalTime().ToString("yyyyMMdd_HHmmss")
            $global:savedLogsPath = "$global:Folder_name\$ArchiveNameUTC.zip"

            $Files | Compress-Archive -DestinationPath $savedLogsPath -Force
            $global:HTMLBody += $global:LineBreaker 
            $global:HTMLBody += "<b>Log files archived</b>"
            $global:HTMLBody += $global:LineBreaker 
            $global:HTMLBody += "<b>$savedLogsPath</b>"
            $global:HTMLBody += $global:LineBreaker
            $global:HTMLBody += $global:LineBreaker
        }
        else
        {
            $global:HTMLBody += $global:LineBreaker 
            $global:HTMLBody += "<b>No log files found inside </b>"
            $global:HTMLBody += $global:LineBreaker
            $global:HTMLBody += "      " + $path
            If ($path -ne $PathFromReg) 
            {
                $global:HTMLBody += $global:LineBreaker
                $global:HTMLBody += " and " + $global:LineBreaker
                $global:HTMLBody += $PathFromReg
                $global:HTMLBody += $global:LineBreaker
            }
            $global:HTMLBody += $global:LineBreaker
            $global:HTMLBody += $global:LineBreaker
        }

    }
    catch
    {
        Write-Warning $_.Exception.Message
        $global:HTMLBody += "<p>Somthing went wrong. $($_.Exception.Message)</p>"
    }
}

#================================================================#
# Generate the HTML report and output to file
#================================================================#
Function generateReport{	
    Write-Host 'Generating HTML Report' -ForegroundColor $outputColor
    Write-Verbose "Producing HTML report"
        
    $ReporTime = Get-Date

    $ReportTimeUTC =  [datetime]::Now.ToUniversalTime()

    #Common HTML head and styles
	$htmlhead="<html>
				<style>
				    BODY{font-family: Consolas,Arial; font-size: 10pt;}
				    H1{font-size: 20px;}
				    H2{font-size: 18px;}
				    H3{font-size: 14px;font-weight: bold; color:blue}
                    H4{font-size: 12px; color:blue}
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
				<h1>Server Name: $global:ComputerName</h1>
				<h3>Generated Local: $reportime</h3>
                <h3>Generated (UTC): $ReportTimeUTC</h3>"
    
    $global:HTMLBody += $LineBreaker
    $global:HTMLBody += $LineBreaker
    
    $htmltail = "</body>
			</html>"

    $HTMLReport = $htmlhead + $global:HTMLBody + $htmltail

    $HTMLReport | Out-File $global:HTMLFile -Encoding Utf8

    Write-host " "
    Write-host "-------------------------------------------------------"
    Write-host "Report generated:" -ForegroundColor Green -BackgroundColor Black 
    Write-host $global:HTMLFile -ForegroundColor Green -BackgroundColor Black 

    if($global:savedLogsPath)
    {
        Write-host $global:savedLogsPath -ForegroundColor Green -BackgroundColor Black 
    }
}


##################################################################
#
#   Script starts running here
#
##################################################################

Write-Host ''
Write-Host '============================================='
Write-Host ' ✪ Azure AD Connect Health Reporting Tool ✪  ' -ForegroundColor Cyan 
Write-Host '============================================='
Write-Host ''

    AADCHRole 
    
    agentDetails

    CSInfo 

    OSInfo     

    dotNetVersion

    NICInfo     
    
    Proxy_AADCH
    
    Proxy_IE
    
    Proxy_netsh
    
    Proxy_machineConfig
    
    Proxy_BITSAdmin
    
    Proxy_Notes
    
    encryptionAlgorithm
    
    TLS12
    
    rootCA 
    
    PerfCounters
    
    connectivityTest    
  
    collectLogs

    pageFiles
    
    logicalDisk
    
    softwareInfo
    
    hotfixes
    
    servicesInfo

    generateReport	

Write-Host ''
Write-Host '============================================='
Write-Host ' ✪         AADCHRep Tool completed         ✪  ' -ForegroundColor Cyan 
Write-Host '============================================='
Write-Host ''
Write-Host "Please provide any feedback, comment or suggestion" -ForegroundColor Yellow
