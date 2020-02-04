from galvatron_lib.core.regex_module import RegexModule

class Module(RegexModule):
    meta = {
            "name": "Powershell script regex Scanner",
            "author": "Lukasz Malendowicz",
            "description": "Uses regexes to search for potentially dangerous Powershell code",
            "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
    }

    def file_name_regex(self):
        return ".*\.ps1"

    def line_regex(self):
        return [
               	(".*Mimikatz.*|.*powercat.*", "Hacking Tool"),
		(".*Set-ExecutionPolicy.*", "Changing execution policy settings"),
		(".*EncodedCommand.*|.*Base64ToString.*|.*StringtoBase64.*|.*Invoke-Encode.*|.*Invoke-Decode.*", "Encoding or running encoded data"),
		(".*Find-AVSignature.*", "Probing for Antivirus"),
		(".*Invoke-DllEncode.*|.*Invoke-PSInject.*|.*Invoke-FindPathHijack.*|.*Invoke-FindDLLHijack.*|.*DllInjection.*|.*ReflectivePEInjection.*", "Attempting to inject dll/exe into memory/existing process"),
		(".*Invoke-Shellcode.*|.*Invoke--Shellcode.*|.*Invoke-ShellcodeMSIL.*|.*Execute-DNSTXT-Code.*", "Attempting to execute shellcode"),
		(".*Get-GPPPassword.*", "Attempting to retrieve plaintext passwords and other information for accounts pushed throug GPP"),
		(".*Get-Keystrokes.*|.*Parse_Keys.*", "Keylogging"),
		(".*Get-TimedScreenshot.*", "Takes screenshots at a regular interval and saved them to the disk"),
		(".*Get-VaultCredential.*", "Attempts to retrieve plaintext windows vault credentials"),
		(".*Invoke-CredentialInjection.*|.*Invoke-TokenManipulation.*", "Attempting to create new processes using other user credentials"),
		(".*Invoke-NinjaCopy.*", "Allow to open already opened files. can be used to retrive NTDS.dit and SYSTEM registery hives"),
		(".*Out-Minidump.*", "Memory Dumping"),
		(".*Set-MasterBootRecord.*", "Attempting to overwrite the master boot record"),
		(".*New-ElevatedPersistenceOption.*|.*Add-Persistence.*|.*Remove-Persistence.*", "Modifying file/service persistance on the system"),
		(".*Invoke-CallbackIEX.*", "Searches for calback machanisms and if it finds one it attempts to execute encoded payload"),
		(".*Get-ServiceUnquoted.*|.*Get-ServicePerms.*|.*Get-ServiceEXEPerms.*", "Collecting data about system services"),
		(".*Invoke-ServiceUserAdd.*", "Attempting to modify a modifiable service to create a user and add it to the local administrators"),
		(".*Invoke-ServiceCMD.*", "Attempting to execute an arbitrary command through service abuse"),
		(".*Write-UserAddMSI.*", "Writes out a precompiled MSI installer that prompts for a user/group addition"),
		(".*Write-ServiceEXECMD.*", "Attempts to replace a service binary with one that executes a custom command"),
		(".*Write-ServiceEXE.*", "Attempts to replace a service binary with one that adds a local administrator user"),
		(".*Restore-ServiceEXE.*|.*Invoke-ServiceStart.*|.*Invoke-ServiceStop.*|.*Invoke-ServiceEnable.*|.*Invoke-ServiceDisable.*", "System services manipulation"),
		(".*Get-RegAlwaysInstallElevated.*|.*Get-RegAutoLogon.*", "Check registry for flags allowing for Priv Esc"),
		(".*Get-UnattendedInstallFiles.*", "Checking unattended installation files for deployment credentials"),
		(".*Get-Webconfig.*", "Attempts to recover cleartext and encrypted connection strings from all web.config files"),
		(".*Get-ApplicationHost.*", "Attempting to recover encrypted application pool and virtual directory passwords from the applicationHost.config"),
		(".*Invoke-AllChecks.*|.*Invoke-MassCommand.*|.*Invoke-MassMimikatz.*|.*Invoke-MassSearch.*|.*Invoke-MassTemplate.*|.*Invoke-MassTokens.*", "Running suspicious command on multiple machines"),
		(".*DNS_TXT_Pwnage.*|.*Invoke-ADSBackdoor.*|.*Gupt-Backdoor.*|.*Add-ScrnSaveBackdoor.*|.*HTTP-Backdoor.*", "Attempting to set/use Backdoor"),
		(".*Execute-OnTime.*", "Control execution time, Could be used to bypass behavioral scanners"),
		(".*Write-UserAddServiceBinary.*|.*Write-CMDServiceBinary.*|.*Out-Word.*|.*Out-Excel.*|.*Out-Java.*|.*Out-Shortcut.*|.*Out-CHM.*|.*Out-HTA.*|.*TexttoEXE.*", "Generating file which could be used to run Commands"),
		(".*Invoke-PowerShellWmi.*|.*Invoke-PowerShellIcmp.*|.*Invoke-PowerShellUdp.*|.*Invoke-PoshRatHttps.*|.*Invoke-PowerShellTcp.*|.*Invoke-PoshRatHttp.*|.*Remove-PoshRat.*", "Reverse powershell shell"),
		(".*Invoke-PSGcat.*|.*Invoke-PsGcatAgent.*", "Code delievery/execution system via Gmail"),
		(".*Enable-DuplicateToken.*", "Duplicates Lsass access token and sets it for the current process"),
		(".*Remove-Update.*", "Attempting to downgrade the system"),
		(".*Download-Execute-PS.*|.*Download_Execute.*", "Attempting to download and execute powershell script"),
		(".*Execute-Command-MSSQL.*", "Attempting to execute remote powershell script on MS SQL server"),
		(".*Get-PassHashes.*", "Attempting to dump password hashes"),
		(".*Invoke-CredentialsPhish.*", "Opens user credential prompt"),
		(".*Get-LsaSecret.*", "Attempting to extract LSA Secrets"),
		(".*Get-Information.*", "Collecting data about the system"),
		(".*Invoke-MimikatzWDigestDowngrade.*", "Attempting to dump passwords in plain text from Windows 8.1 and Server 2012 onwards"),
		(".*Copy-VSS.*", "Attempting to copy the SAM file (and ntds.dit and SYSTEM hive if run on a Domain Controller"),
		(".*Check-VM.*", "Check for Virtual machines on the system "),
		(".*Invoke-NetworkRelay.*", "Attempting to run netsh port forwarding/relaying commands on remote computers"),
		(".*Create-MultipleSessions.*", "Looking for credentials on remote computers and attempt to open PSSessions if the credentials are found"),
		(".*Run-EXEonRemote.*", "Attempting to drop and execute executables on multiple computers"),
		(".*Invoke-BruteForce.*", "Bruteforcing SQL Server, Active Directory, Local Accounts, Web and FTP"),
		(".*Port-Scan.*", "Scanning IP addresses, Ports and Hostnames"),
		(".*Add-Exfiltration.*|.*Do-Exfiltration.*", "Attempting to exfiltrate data"),
		(".*Invoke-CreateCertificate.*", "Possible attempt to intercepting network traffic"),
		(".*Find-PSServiceAccounts.*", "Searching AD for user accounts configured with a ServicePrincipalName"),
		(".*Get-PSADForestKRBTGTInfo.*", "Searching AD for all of the KRBTGT accounts"),
		(".*Discover-PSMSExchangeServers.*|.*Discover-PSMSSQLServers.*|.*Discover-PSInterestingServices.*", "Attempting to discover Microsoft Exchange,MS SQL servers or interesting network services without port scanning"),
		(".*Get-PSADForestInfo.*", "Collecting info about Active Directory"),
		(".*Get-KerberosPolicy.*", "Collecting info about Kerbros Policy on the system"),
		(".*Payload.*", "Portntially dangerous function"),
                ]






