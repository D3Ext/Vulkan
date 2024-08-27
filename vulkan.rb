#!/usr/bin/env ruby

# Vulkan: Offensive tool to obfuscate powershell payloads
# Author: D3Ext
# Github: https://github.com/D3Ext
# Blog: https://d3ext.github.io
# Contact: <d3ext@proton.me>

# Use this tool under your own responsability!

# Import gems
require "colorize"
require "optparse"

# This array stores generated random strings to avoid collisions
$obfuscated_strings = []

# This array contains some of the most important cmdlets that may be worth to obfuscate
$known_cmdlets = ["Add-Computer","Add-Content","Add-EtwTraceProvider","Add-History","Add-JobTrigger","Add-KdsRootKey","Add-LocalGroupMember","Add-Member","Add-MpPreference","Add-NetEventProvider","Add-NetEventVFPProvider","Add-NetEventVmSwitch","Add-OdbcDsn","Add-PSSnapin","Add-PhysicalDisk","Add-Printer","Add-PrinterDriver","Add-PrinterPort","Add-StorageFaultDomain","Add-Type","Add-VpnConnection","Add-VpnConnectionRoute","Add-WindowsCapability","Add-WindowsDriver","Add-WindowsImage","Add-WindowsPackage","Clear-Content","Clear-Disk","Clear-DnsClientCache","Clear-EventLog","Clear-History","Clear-Host","Clear-Item","Clear-ItemProperty","Clear-Recyclebin","Clear-Tpm","Clear-Variable","Close-SmbOpenFile","Close-SmbSession","Compare-Object","Complete-BitsTransfer","Complete-Transaction","Compress-Archive","Connect-PSSession","Convert-Path","Convert-String","ConvertFrom-SecureString","ConvertFrom-String","ConvertFrom-StringData","ConvertTo-Csv","ConvertTo-Html","ConvertTo-Json","ConvertTo-SecureString","ConvertTo-Xml","Copy-BcdEntry","Copy-Item","Copy-ItemProperty","Copy-NetFirewallRule","Copy-NetIPsecRule","Debug-FileShare","Debug-Process","Debug-Runspace","Disable-DscDebug","Disable-JobTrigger","Disable-LocalUser","Disable-MMAgent","Disable-NetAdapter","Disable-NetAdapterBinding","Disable-NetFirewallRule","Disable-OdbcPerfCounter","Disable-PSBreakpoint","Disable-PSRemoting","Disable-PSTrace","Disable-PnpDevice","Disable-RunspaceDebug","Disable-ScheduledJob","Disable-ScheduledTask","Enable-ComputerRestore","Enable-DscDebug","Enable-JobTrigger","Enable-LocalUser","Enable-MMAgent","Enable-NetAdapter","Enable-PSRemoting","Enable-PSSessionConfiguration","Enable-ScheduledJob","Enable-ScheduledTask","Enable-SmbDelegation","Enable-StorageBusDisk","Enter-PSHostProcess","Enter-PSSession","Exit-PSHostProcess","Exit-PSSession","Expand-Archive","Export-Alias","Export-Certificate","Export-Clixml","Export-Console","Export-Counter","Export-Csv","Export-FormatData","Export-ModuleMember","Export-ODataEndpointProxy","Export-PSSession","Export-PfxCertificate","Export-ScheduledTask","Export-StartLayout","Export-Trace","Export-WindowsDriver","Export-WindowsImage","Find-Command","Find-DscResource","Find-Module","Find-NetIPsecRule","Find-NetRoute","Find-Package","Find-PackageProvider","Find-RoleCapability","Find-Script","Flush-Volume","ForEach-Object","Format-Custom","Format-Hex","Format-List","Format-Table","Format-Volume","Format-Wide","Get-Acl","Get-Alias","Get-BitsTransfer","Get-Certificate","Get-ChildItem","Get-CimClass","Get-CimInstance","Get-CimSession","Get-Clipboard","Get-CmsMessage","Get-Command","Get-ComputerInfo","Get-Content","Get-Counter","Get-Credential","Get-Culture","Get-Date","Get-Disk","Get-DiskImage","Get-DiskSNV","Get-DnsClient","Get-DnsClientCache","Get-DscConfiguration","Get-DscResource","Get-Dtc","Get-DtcDefault","Get-DtcLog","Get-DtcTransaction","Get-EtwTraceProvider","Get-EtwTraceSession","Get-Event","Get-EventLog","Get-EventSubscriber","Get-ExecutionPolicy","Get-FileHash","Get-FileShare","Get-FileStorageTier","Get-FormatData","Get-Help","Get-History","Get-Host","Get-HotFix","Get-InitiatorId","Get-IscsiConnection","Get-IscsiSession","Get-IscsiTarget","Get-IscsiTargetPortal","Get-IseSnippet","Get-Item","Get-ItemProperty","Get-Job","Get-JobTrigger","Get-Language","Get-LapsAADPassword","Get-LapsADPassword","Get-LapsDiagnostics","Get-LocalGroup","Get-LocalGroupMember","Get-LocalUser","Get-Location","Get-LogProperties","Get-MMAgent","Get-MaskingSet","Get-Member","Get-Module","Get-MpComputerStatus","Get-MpPreference","Get-MpThreat","Get-MpThreatCatalog","Get-NetFirewallProfile","Get-NetIPAddress","Get-NetIPConfiguration","Get-NetIPHttpsConfiguration","Get-NetIPHttpsState","Get-NetIPInterface","Get-NetNat","Get-NetNatGlobal","Get-NetNatSession","Get-NetPrefixPolicy","Get-NetView","Get-PSBreakpoint","Get-PSCallStack","Get-PSDrive","Get-PSHostProcessInfo","Get-PSProvider","Get-PSRepository","Get-PSSession","Get-Package","Get-PackageProvider","Get-PackageSource","Get-Partition","Get-PartitionSupportedSize","Get-PfxCertificate","Get-PfxData","Get-PhysicalDisk","Get-PhysicalExtent","Get-PrintConfiguration","Get-PrintJob","Get-Printer","Get-PrinterDriver","Get-PrinterPort","Get-PrinterProperty","Get-Process","Get-ProcessMitigation","Get-Random","Get-ResiliencySetting","Get-Runspace","Get-RunspaceDebug","Get-ScheduledJob","Get-ScheduledTask","Get-ScheduledTaskInfo","Get-SecureBootPolicy","Get-SecureBootUEFI","Get-Service","Get-SmbConnection","Get-SmbDelegation","Get-SmbGlobalMapping","Get-SmbMapping","Get-SmbOpenFile","Get-SmbSession","Get-SmbShare","Get-SmbShareAccess","Get-SmbWitnessClient","Get-StartApps","Get-StorageBusBinding","Get-StorageBusCache","Get-StorageBusDisk","Get-StorageHistory","Get-StorageJob","Get-StorageNode","Get-StoragePool","Get-StorageProvider","Get-StorageSubSystem","Get-StorageTier","Get-SystemLanguage","Get-TargetPort","Get-TargetPortal","Get-TestDriveItem","Get-TimeZone","Get-TlsCipherSuite","Get-TlsEccCurve","Get-Tpm","Get-TraceSource","Get-Transaction","Get-TypeData","Get-UICulture","Get-Unique","Get-Variable","Get-Verb","Get-VirtualDisk","Get-Volume","Get-VpnConnection","Get-WIMBootEntry","Get-WSManCredSSP","Get-WSManInstance","Get-WdacBidTrace","Get-WinEvent","Get-WinSystemLocale","Get-WindowsDriver","Get-WindowsEdition","Get-WindowsImage","Get-WindowsImageContent","Get-WindowsPackage","Get-WindowsUpdateLog","Get-WinhttpProxy","Get-WmiObject","Group-Object","Hide-VirtualDisk","Import-Alias","Import-BcdStore","Import-BinaryMiLog","Import-Certificate","Import-Clixml","Import-Counter","Import-Csv","Import-IseSnippet","Import-LocalizedData","Import-Module","Import-PSSession","Import-StartLayout","Import-TpmOwnerAuth","Import-WinhttpProxy","Initialize-Disk","Initialize-Tpm","Initialize-Volume","Install-Dtc","Install-Language","Install-Module","Install-Package","Install-PackageProvider","Install-Script","Invoke-Command","Invoke-CommandInDesktopPackage","Invoke-DscResource","Invoke-Expression","Invoke-History","Invoke-Item","Invoke-Pester","Invoke-RestMethod","Invoke-WSManAction","Invoke-WebRequest","Invoke-WmiMethod","Join-Path","Limit-EventLog","Lock-BitLocker","Measure-Command","Measure-Object","Mount-DiskImage","Mount-WindowsImage","Move-Item","Move-ItemProperty","Move-SmbClient","New-Alias","New-AutologgerConfig","New-BcdEntry","New-BcdStore","New-CimInstance","New-CimSession","New-CimSessionOption","New-DscChecksum","New-EapConfiguration","New-EtwTraceSession","New-Event","New-EventLog","New-FileCatalog","New-FileShare","New-Fixture","New-Guid","New-Item","New-ItemProperty","New-JobTrigger","New-LocalGroup","New-LocalUser","New-MaskingSet","New-Module","New-Object","New-PSDrive","New-PSRoleCapabilityFile","New-PSSession","New-PSSessionOption","New-PSTransportOption","New-PSWorkflowSession","New-Partition","New-PesterOption","New-PmemDedicatedMemory","New-PmemDisk","New-ProvisioningRepro","New-ScheduledJobOption","New-ScheduledTask","New-ScheduledTaskAction","New-ScriptFileInfo","New-SelfSignedCertificate","New-Service","New-SmbGlobalMapping","New-SmbMapping","New-SmbShare","New-StorageBusBinding","New-StorageTier","New-TemporaryFile","New-TimeSpan","New-Variable","New-VirtualDisk","New-VirtualDiskClone","New-Volume","New-WebServiceProxy","New-WinEvent","New-WindowsImage","Open-NetGPO","Out-Default","Out-File","Out-Host","Out-Null","Out-Printer","Out-String","Pop-Location","Protect-CmsMessage","Publish-Module","Publish-Script","Push-Location","Read-Host","Register-PSRepository","Register-PackageSource","Register-ScheduledJob","Register-ScheduledTask","Register-WmiEvent","Remove-BcdEntry","Remove-Computer","Remove-EtwTraceProvider","Remove-EtwTraceSession","Remove-Event","Remove-EventLog","Remove-FileShare","Remove-InitiatorId","Remove-IscsiTargetPortal","Remove-Item","Remove-ItemProperty","Remove-Job","Remove-JobTrigger","Remove-LocalGroup","Remove-LocalGroupMember","Remove-LocalUser","Remove-MaskingSet","Remove-Module","Remove-MpPreference","Remove-MpThreat","Remove-NetFirewallRule","Remove-NetIPAddress","Remove-NetIPsecRule","Remove-NetNat","Remove-NetworkSwitchVlan","Remove-OdbcDsn","Remove-PSDrive","Remove-PSSession","Remove-PSSnapin","Remove-Partition","Remove-PhysicalDisk","Remove-PmemDisk","Remove-PrintJob","Remove-Printer","Remove-PrinterDriver","Remove-PrinterPort","Remove-SMBComponent","Remove-SmbMapping","Remove-SmbShare","Remove-StorageFileServer","Remove-StoragePool","Remove-StorageTier","Remove-TypeData","Remove-Variable","Remove-VirtualDisk","Remove-WSManInstance","Remove-WindowsDriver","Remove-WindowsImage","Remove-WindowsPackage","Remove-WmiObject","Rename-Computer","Rename-Item","Rename-ItemProperty","Rename-LocalGroup","Rename-LocalUser","Rename-MaskingSet","Rename-NetAdapter","Rename-Printer","Repair-FileIntegrity","Repair-VirtualDisk","Repair-Volume","Reset-LapsPassword","Reset-PhysicalDisk","Reset-WinhttpProxy","Resize-Partition","Resize-StorageTier","Resize-VirtualDisk","Restart-Computer","Restart-NetAdapter","Restart-PcsvDevice","Restart-PrintJob","Restart-Service","Restore-Computer","Resume-BitLocker","Resume-BitsTransfer","Resume-Job","Resume-PrintJob","Resume-Service","Resume-StorageBusDisk","Save-EtwTraceSession","Save-Help","Save-Module","Save-NetGPO","Save-Package","Save-Script","Save-SoftwareInventory","Save-WindowsImage","Select-Object","Select-String","Select-Xml","Send-EtwTraceSession","Send-MailMessage","Set-Acl","Set-Alias","Set-BitsTransfer","Set-CimInstance","Set-Clipboard","Set-Content","Set-Culture","Set-DODownloadMode","Set-Date","Set-Disk","Set-DnsClient","Set-EtwTraceProvider","Set-EtwTraceSession","Set-ExecutionPolicy","Set-FileIntegrity","Set-FileShare","Set-FileStorageTier","Set-Item","Set-ItemProperty","Set-JobTrigger","Set-KdsConfiguration","Set-LapsADAuditing","Set-LocalGroup","Set-LocalUser","Set-Location","Set-LogProperties","Set-MMAgent","Set-MpPreference","Set-NetUDPSetting","Set-OdbcDriver","Set-OdbcDsn","Set-PSBreakpoint","Set-PSDebug","Set-PSReadLineOption","Set-PSRepository","Set-PackageSource","Set-Partition","Set-PhysicalDisk","Set-PreferredLanguage","Set-PrintConfiguration","Set-Printer","Set-PrinterProperty","Set-ProcessMitigation","Set-ResiliencySetting","Set-ScheduledJob","Set-ScheduledJobOption","Set-Service","Set-SmbPathAcl","Set-SmbShare","Set-StorageBusProfile","Set-StorageFileServer","Set-StoragePool","Set-StorageProvider","Set-StorageSetting","Set-StorageSubSystem","Set-StorageTier","Set-StrictMode","Set-SystemLanguage","Set-TestInconclusive","Set-TimeZone","Set-TpmOwnerAuth","Set-TraceSource","Set-Variable","Set-VirtualDisk","Set-Volume","Set-WindowsProductKey","Set-WinhttpProxy","Set-WmiInstance","Show-Command","Show-EventLog","Show-NetFirewallRule","Show-NetIPsecRule","Show-StorageHistory","Show-VirtualDisk","Sort-Object","Split-Path","Start-AppBackgroundTask","Start-AutologgerConfig","Start-BitsTransfer","Start-DscConfiguration","Start-Dtc","Start-EtwTraceSession","Start-Job","Start-MpRollback","Start-MpScan","Start-MpWDOScan","Start-NetEventSession","Start-OSUninstall","Start-PcsvDevice","Start-Process","Start-ScheduledTask","Start-Service","Start-Sleep","Start-Trace","Start-Transaction","Start-Transcript","Stop-Computer","Stop-DscConfiguration","Stop-Dtc","Stop-EtwTraceSession","Stop-Job","Stop-NetEventSession","Stop-PcsvDevice","Stop-Process","Stop-ScheduledTask","Stop-Service","Stop-StorageDiagnosticLog","Stop-StorageJob","Stop-Trace","Stop-Transcript","Suspend-BitLocker","Suspend-BitsTransfer","Suspend-Job","Suspend-PrintJob","Suspend-Service","Suspend-StorageBusDisk","Switch-Certificate","Sync-NetIPsecRule","Tee-Object","Test-Certificate","Test-ComputerSecureChannel","Test-Connection","Test-DscConfiguration","Test-Dtc","Test-FileCatalog","Test-KdsRootKey","Test-ModuleManifest","Test-NetConnection","Test-Path","Test-ScriptFileInfo","Test-WSMan","Trace-Command","Update-IscsiTarget","Update-LapsADSchema","Update-List","Update-Module","Update-MpSignature","Update-TypeData","Use-Transaction","Wait-Debugger","Wait-Event","Wait-Job","Wait-Process","Where-Object","Write-Debug","Write-Error","Write-EventLog","Write-FileSystemCache","Write-Host","Write-Information","Write-Output","Write-PrinterNfcTag","Write-Progress","Write-Verbose","Write-VolumeCache","Write-Warning","IEX"]

# This array holds all powershell internal variables to avoid overwriting them
# see here https://ss64.com/ps/syntax-automatic-variables.html
$special_vars = ["$true","$false","$null","$env","$read","$error","$verb","$_","$script","$iswow64","$iswow64process","$$","$?","$^","$args","$consolefilename","$event","$eventargs","$foreach","$home","$host","$input","$iscoreclr","$lastexitcode","$matches","$pid","$profile","$psboundparameters","$pscmdlet","$pshome","$pwd","$shellid","$switch","$this","$entrypoint","$errorview","$ofs","$pscommandpath","$psitem","$psscriptroot","$psversiontable","$stacktrace","$psdebugcontext","$myinvocation","$islinux","$iswindows","$eventsubscriber","$allnodes","$dllname","$namespace","$module"]

$known_namespace_classes = ["io.streamwriter","system.net.sockets.tcpclient","net.sockets.tcpclient","net.webclient","psobject","security.principal.windowsprincipal","system.byte","system.diagnostics.process","system.diagnostics.processstartinfo","system.io.streamwriter","system.net.httplistener","system.net.ipendpoint","system.net.networkinformation.ping","system.net.sockets.tcpclient","system.text.asciiencoding","text.asciiencoding","text.encoding"]

# This array contains all powershell characters with special uses when are combined with a backtick --> `
$no_backticks = "0abefnrtuxv"

# Array used to check if a character is a special one
$special_characters = "?<>',?[]}{=-)(*&^%$#`~{}"

$safe = false
$all = false
$verbose = false
$case_obfs = false

#
# Auxiliary functions
#

# Print ASCII art banner
def ascii()
  banner = '╦  ╦┬ ┬┬  ┬┌─┌─┐┌┐┌
╚╗╔╝│ ││  ├┴┐├─┤│││
 ╚╝ └─┘┴─┘┴ ┴┴ ┴┘└┘
    by D3Ext v0.2
  '
  puts banner.red
end

# Print custom help panel
def show_help_panel()
  puts "Usage of Vulkan:"
  puts "  REQUIRED ARGUMENTS:"
  puts "    -f, --file string     source Powershell script to obfuscate"
  puts "    -o, --output string   store obfuscated script in a file"
  puts
  puts "  OPTIONAL ARGUMENTS:"
  puts "    -a, --all       use all obfuscation techniques"
  puts "    -s, --safe      enable safe obfuscation mode to prevent the script from breaking (use almost all obfuscation techniques) (enabled by default)"
  #puts "    --strings       enable string obfuscation"
  puts "    --vars          enable variable obfuscation"
  puts "    --funcs         enable functions obfuscation"
  puts "    --cmdlets       enable cmdlets obfuscation"
  puts "    --namespaces    enable namespace classes obfuscation"
  puts "    --backticks     enable backticks obfuscation"
  puts "    --case          enable uppercase/lowercase obfuscation"
  puts "    --pipes         enable pipes and pipelines obfuscation"
  puts "    --comments      remove and obfuscate comments"
  puts "    --indentation   add random indentation"
  puts "    --ips           obfuscate IP adddresses by converting them to hex format"
  puts
  puts "  EXTRA:"
  puts "    -v, --verbose   enable verbose"
  puts "    -d, --debug     enable debug mode to check how obfuscation works"
  puts "    -h, --help      show help panel"
  puts "    --about         show information about how to use this tool"
  puts
  puts "Examples:"
  puts "  vulkan.rb -f script.ps1 -o output.ps1 --verbose"
  puts "  vulkan.rb -f script.ps1 -o output.ps1 --all"
  puts "  vulkan.rb -f script.ps1 -o output.ps1 --vars --cmdlets"
end

# Show information related to this tool and its usage
def show_about_panel()
  puts "Vulkan obfuscated Powershell code to prevent it from being detected by antivirus solutions. To do so, it uses regular expressions (to parse the data) and logical operators (to create semi-random data)."
  puts "This tool contains 3 different modes: safe, all and custom"
  puts "Safe mode (--safe) is enabled by default and it will perform most of the obfuscation techniques to grant the best safety and obfuscation at the same time. However, you can use --all to enable all obfuscation techniques (it should not break the script). Custom mode allows you to enable the best obfuscation techniques for your needs."
end

# Parse CLI arguments
def parseArgs()
  options = {}
  opt_parser = OptionParser.new do |opts|
    opts.banner = 'Usage: main.rb [options]'
    opts.separator "Example: main.rb -f script.ps1 -o obfuscated.ps1"
    opts.separator ""
    
    opts.on("-f FILE", "--file FILE", "") do |file|
      options[:file] = file
    end

    opts.on("-o DEST", "--output DEST", "") do |output|
      options[:output] = output
    end

    # DONE
    opts.on("-a", "--all", "") do |all|
      options[:all]= all
    end

    # DONE
    opts.on('-s', '--safe', '') do |safe|
      options[:safe] = safe
    end

    #opts.on('', '--strings', '') do |strings|
      #options[:strings] = strings
    #end

    # DONE
    opts.on('', '--vars', '') do |vars|
      options[:vars] = vars
    end

    # DONE
    opts.on('', '--funcs', '') do |funcs|
      options[:funcs] = funcs
    end

    # DONE
    opts.on('', '--cmdlets', '') do |cmdlets|
      options[:cmdlets] = cmdlets
    end

    # DONE
    opts.on('', '--namespaces', '') do |namespaces|
      options[:namespaces] = namespaces
    end

    # DONE
    opts.on('', '--backticks', '') do |backticks|
      options[:backticks] = backticks
    end

    # DONE
    opts.on('', '--case', '') do |c|
      options[:case] = c
    end

    # DONE
    opts.on('', '--pipes', '') do |pipes|
      options[:pipes] = pipes
    end

    # DONE
    opts.on('', '--comments', '') do |comments|
      options[:comments] = comments
    end

    # DONE
    opts.on('', '--indentation', '') do |indentation|
      options[:indentation] = indentation
    end

    # DONE
    opts.on('', '--ips', '') do |ips|
      options[:ips] = ips
    end

    # DONE
    opts.on('', '--special', '') do |special|
      options[:special] = special
    end

    # OONE
    opts.on('-v', '--verbose', '') do |verbose|
      options[:verbose] = verbose
    end

    opts.on('-d', '--debug', '') do |debug|
      options[:debug] = debug
    end

    # DONE
    opts.on('-h', '--help', '') do |help|
      options[:help] = help
    end

    # DONE
    opts.on('', '--about', '') do |about|
      options[:about] = about
    end

  end

  opt_parser.parse!(ARGV)
  return options
end

# Receive content to write to file and filename
def write_content(f_content, output_file)
  f = File.open(output_file, "w")
  f.write(f_content)
end


#
# Obfuscation functions
#

# Generate a random string based on given length
# see here https://stackoverflow.com/questions/88311/how-to-generate-a-random-string-in-ruby
def generate_rand_str(num)
  o = [('a'..'z'), ('A'..'Z')].map(&:to_a).flatten
  
  if num < 5
    num = 5
  end

  while true
    # Add some randomization by
    # substracting 1, adding 1 or nothing
    x = (1..3).to_a.sample

    case x
    when 1
      rand_str = (0...(num - 1)).map { o[rand(o.length)] }.join
    when 2
      rand_str = (0...(num + 1)).map { o[rand(o.length)] }.join
    when 3
      rand_str = (0...num).map { o[rand(o.length)] }.join
    end

    if $obfuscated_strings.include?(rand_str) == false
      $obfuscated_strings.append(rand_str)
      break
    end
    
    $obfuscated_strings.append(rand_str)
  end

  return rand_str
end

# This function receives a string, iterates
# over its characters using random numbers
# between 1 and 2 and then checks if it's
# even or odd to lowercase or upcase the character
# (i.e. Get-Command to geT-COMmaNd)
def obfuscate_word_case(str_to_mod)
  mod_str = ""

  str_to_mod.split("").each { |str_char|
    rand_num = (1..2).to_a.sample

    if (rand_num % 2) == 0
      mod_str += str_char.downcase
    else
      mod_str += str_char.upcase
    end
  }

  return mod_str
end

# Obfuscation technique which adds ` between characters
# to avoid static detection but avoiding some special characters
# (i.e. Invoke-Mimikatz to `Inv`o`ke-`Mim`i`kat`z)
def add_backticks_to_word(str_to_mod)
  moded_str = ""

  str_to_mod.split("").each{ |str_char|
    if $special_characters.include?(str_char) == true
      moded_str += str_char
      next
    end

    if $no_backticks.include?(str_char) == true
      moded_str += str_char
      next
    else
      # Use random numbers to obfuscate it
      # as much as possible
      # 66% of probability to add a backtick
      rand_num = (2..4).to_a.sample
      if (rand_num % 2) == 0
        moded_str += "`" + str_char
      else
        moded_str += str_char
      end
    end
  }

  return moded_str
end


#
# Main obfuscation functions
#

def obfuscate_strings(file_data)
  if $verbose
    puts "[*] Obfuscating strings...".blue
  end

  strings1 = file_data.scan(/(?<=").+?(?=")/)
  strings2 = file_data.scan(/(?<=').+?(?=')/)
  strings3 = file_data.scan(/(?<=\.)[\w]+?(?=\()/)

  strings = [strings1, strings2, strings3].reduce([], :concat)
  strings.uniq!

  # TODO

  return file_data
end

def obfuscate_variables(file_data)
  if $verbose
    puts "[*] Obfuscating variables...".blue
  end

  variables = file_data.scan(/\$[\w|_]+/)
  variables.uniq!

  variables.each { |var|
    if !$special_vars.include?(var.downcase)
      new_var = "$" + generate_rand_str(10)
      file_data.gsub!(var, new_var)
    end
  }

  return file_data
end

def obfuscate_functions(file_data)
  if $verbose
    puts "[*] Obfuscating functions...".blue
  end

  # This returns an array of arrays so it has to be converted to a single array
  found_functions = file_data.scan(/function\s+([\w|\_|\-]+)\s*\{/m)

  functions = []
  found_functions.each { |entry|
    functions.append(entry[0])
  }

  # Sort array by descending length to avoid function collisions
  functions = functions.sort_by {|x| -x.length}

  # Iterate over functions
  functions.each { |func|
    if func.length > 5

      new_func = generate_rand_str(12)

      if func.include? ":"
        func = func.split(":")[1]
        prefix = func.split(":")[0]

        file_data.gsub!("function #{prefix}:#{func}", "function #{prefix}:#{new_func}")
        file_data.gsub!(/#{Regexp.escape func}/i, new_func)
      else
        file_data.gsub!("function #{func}", "function #{new_func}")
        file_data.gsub!(/#{Regexp.escape func}/i, new_func)
      end

    end
  }

  return file_data
end

def obfuscate_cmdlets(file_data)
  if $verbose
    puts "[*] Obfuscating cmdlets...".blue
  end

  $known_cmdlets.each{ |cmdlet|

    if file_data.downcase.include? "#{cmdlet.downcase}"
      cmdlet_rand_num = (1..3).to_a.sample

      if cmdlet_rand_num == 1
        if $case_obfs == true
          moded_str = add_backticks_to_word(obfuscate_word_case(cmdlet))
        else
          moded_str = add_backticks_to_word(cmdlet)
        end

      elsif cmdlet_rand_num == 2
        moded_str = "&([string]::join('', ( ("
        cmdlet.bytes.map { |x|
          moded_str += x.to_s + ","
        }

        moded_str.chop! # Remove trailing comma
        moded_str += ") |%{ ( [" + obfuscate_word_case("char") + "][" + obfuscate_word_case("int") + "] $_)})))"
      elsif cmdlet_rand_num == 3
        raw_str = ""
        moded_str = "&((\""

        cmdlet.split("").each { |char|
          rand_num = (1..4).to_a.sample
          rand_str = generate_rand_str(rand_num)

          if (rand_num % 2) == 0
            moded_str += char + rand_str
            raw_str += char + rand_str
          else
            moded_str += rand_str + char
            raw_str += rand_str + char
          end
        }
        moded_str += "\")["
        
        cmdlet.split("").each { |char|
          moded_str += raw_str.index(char).to_s + ","
        }

        moded_str.chop!
        moded_str += "] -join '')"
      end

      file_data.gsub!(/#{Regexp.escape cmdlet}/i, moded_str)
    end
  }

  return file_data
end

def obfuscate_namespaces(file_data)
  if $verbose
    puts "[*] Obfuscating namespace classes...".blue
  end

  $known_namespaces_classes = $known_namespace_classes.sort_by {|x| -x.length}

  # Iterate over every single namespace
  $known_namespace_classes.each{ |namespace|
    # Check if it is included in the payload to obfuscate
    if file_data.downcase.include? "#{namespace}"

      moded_str = "$("
      # Iterate over every character
      namespace.split("").each{ |char|
        rand_num = (1..100).to_a.sample
        rand_type = (1..7).to_a.sample

        # Check if case obfuscation is enabled to obfuscate the word "char"
        if $case_obfs
          moded_str += "[" + obfuscate_word_case("char") + "]"
        else
          moded_str += "[char]"
        end

        # Check the obfuscation mode 
        if rand_type == 1
          moded_str += "(#{rand_num}+#{char.ord}-#{rand_num})+"
        elsif rand_type == 2
          moded_str += "(#{rand_num}*#{char.ord}/#{rand_num})+"
        elsif rand_type == 3
          moded_str += "(#{char.ord}*#{rand_num}/#{rand_num})+"
        elsif rand_type == 4
          moded_str += "(0+#{char.ord}+0)+"
        elsif rand_type == 5
          moded_str += "(0+#{char.ord}-0)+"
        elsif rand_type == 6
          moded_str += "(#{char.ord}+#{rand_num}-#{rand_num})+"
        elsif rand_type == 7
          moded_str += "(#{char.ord}-#{rand_num}+#{rand_num})+"
        end
      }

      # Remove trailing "+" symbol
      moded_str.chop!
      moded_str += ")"

      # Finally replace all matches in the payload
      file_data.gsub!(/#{Regexp.escape namespace}/i, moded_str)
    end
  }

  return file_data
end

def obfuscate_backticks(file_data)
  if $verbose == true
    puts "[*] Adding backticks...".blue
  end

  # This returns an array of arrays so it has to be converted to a single array
  found_functions = file_data.scan(/function\s+([\w|\_|\-]+)\s*\{/m)

  functions = []
  found_functions.each { |entry|
    functions.append(entry[0])
  }

  # Sort array by descending length to avoid function collisions
  functions = functions.sort_by {|x| -x.length}

  functions.each{ |func|
    if func.include? ":"
      func = func.split(":")[1]
    end

    if $case_obfs == true
      file_data.gsub!(/#{Regexp.escape func}/, add_backticks_to_word(obfuscate_word_case(func)))
    else
      file_data.gsub!(/#{Regexp.escape func}/i, add_backticks_to_word(func))
    end
  }

  return file_data
end

def obfuscate_pipes(file_data)
  if $verbose == true
    puts "[*] Obfuscating pipes...".blue
  end

  # Iterate over every payload line to check if it contains a pipe
  file_data.each_line{ |line|
    if line.include? "|"
      pipe_rand_num = (1..7).to_a.sample

      # In case a pipe is present on the current line, then check the obfuscation technique to use
      case pipe_rand_num
      when 1
        moded_line = line.gsub("|", "|%{$_}|")
      when 2
        moded_line = line.gsub("|", "|<##>%{$_}|")
      when 3
        moded_line = line.gsub("|", "|%{$_}<##>|")
      when 4
        moded_line = line.gsub("|", "|<##>%{$_}<##>|")
      when 5
        moded_line = line.gsub("|", "|%{;$_}|")
      when 6
        moded_line = line.gsub("|", "|%{$_;}|")
      when 7
        moded_line = line.gsub("|", "|%{;$_;}|")
      end

      # Replace line with obfuscated pipe
      file_data.gsub!(line, moded_line)
    end
  }

  return file_data
end
  
def obfuscate_comments(file_data)
  if $verbose == true
    puts "[*] Removing multi-line comments...".blue
    puts "[*] Removing single-line comments...".blue
  end

  # Remove multi-line comments using regexp
  comments = file_data.scan(/(<#.*?#>)/m)
  comments.each { |str_lines|
    str_lines.each { |entry|
      file_data.gsub!(entry, "")
    }
  }

  # Remove single line comments using regexp
  file_data.gsub!(/^\s*#.*$/, '')

  # Remove empty lines using regexp
  file_data.gsub!(/^(?:[\t ]*(?:\r?\n|\r))+/, '')  

  return file_data
end

def obfuscate_indentation(file_data)
  if $verbose == true
    puts "[*] Obfuscating indentation...".blue
  end

  # Iterate over every line of the payload
  file_data.each_line{ |line|
    # Generate random number between 1 and 7
    indentation_rand_num = (1..7).to_a.sample

    # Check if random number is either 1 or 2 to add extra indentation (propability is 2/7)
    if indentation_rand_num == 1 || indentation_rand_num == 2
      # Generate random number of extra tabs to add
      tabs_to_add = (1..3).to_a.sample

      total_tabs = "  " * tabs_to_add
      moded_line = total_tabs + line

      # Replace original line
      file_data.gsub!(line, moded_line)
    end
  }

  return file_data
end

def obfuscate_ips(file_data)
  if $verbose == true
    puts "[*] Converting IP addresses to hex...".blue
  end

  ip_addresses = file_data.scan(/(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])/m)

  ip_addresses.each{ |ip|
    octets = ip.split('.').map(&:to_i)
    hex_octets = octets.map { |octet| octet.to_s(16).rjust(2, '0') }
    hex_ip = hex_octets.join

    final_hex_ip = "0x#{hex_ip.upcase}"
    file_data.gsub!(ip, final_hex_ip)
  }

  return file_data
end

def obfuscate_special_vars(file_data)
  if $verbose
    puts "[*] Obfuscating special variables...".blue
  end

  ["$true", "$false", "$null"].each{ |var|
    if file_data.include? var
      rand_num = (1..2).to_a.sample

      if rand_num == 1
        file_data.gsub!(/#{Regexp.escape var}/i, obfuscate_word_case(var))
      elsif rand_num == 2
        new_var = generate_rand_str(10)
        file_data.gsub!(/#{Regexp.escape var}/i, "$#{new_var}")

        if $case_obfs
          moded_var = obfuscate_word_case(var)
          file_data = "$#{new_var} = #{moded_var}\n" + file_data
        else
          file_data = "$#{new_var} = #{var}\n" + file_data
        end
      end
    end
  }

  # Return obfuscated content
  return file_data
end

# This function apply all obfuscation technique over given Powershell script
def obfuscate_all(file_data)
  file_data = obfuscate_comments(file_data)

  #file_data = obfuscate_strings(file_data)

  file_data = obfuscate_variables(file_data)

  file_data = obfuscate_functions(file_data)

  file_data = obfuscate_cmdlets(file_data)

  file_data = obfuscate_namespaces(file_data)

  file_data = obfuscate_backticks(file_data)

  file_data = obfuscate_pipes(file_data)

  file_data = obfuscate_indentation(file_data)

  file_data = obfuscate_ips(file_data)

  # Return obfuscated content
  return file_data
end

def obfuscate_safe(file_data)

  file_data = obfuscate_comments(file_data)

  file_data = obfuscate_variables(file_data)

  file_data = obfuscate_functions(file_data)

  file_data = obfuscate_cmdlets(file_data)

  file_data = obfuscate_namespaces(file_data)

  file_data = obfuscate_backticks(file_data)

  file_data = obfuscate_pipes(file_data)

  # Return obfuscated content
  return file_data
end

def main()
  # Print banner
  ascii()

  # Parse CLI args
  opts = parseArgs()

  # Check if user shows help panel
  if opts[:help]
    show_help_panel()
    exit 0
  end

  if opts[:about]
    show_about_panel
    exit 0
  end

  # Check required file parameter
  if !opts[:file]
    puts "[!] File parameter missing. See --help for help"
    exit 0
  end

  # Check required output file parameter
  if !opts[:output]
    puts "[!] Output parameter missing. See --help for help"
    exit 0
  end

  if opts[:verbose]
    $verbose = true
  else
    $verbose = false
  end

  # Check whether user wants to use all, safe or custom obfuscation techniques
  if opts[:case] || opts[:vars] || opts[:funcs] || opts[:cmdlets] || opts[:namespaces] || opts[:backticks] || opts[:comments] || opts[:indentation] || opts[:ips] || opts[:special]
    puts "[+] Using custom obfuscation techniques".green
  elsif !opts[:all] && !opts[:safe]
    puts "[+] Using safe obfuscation techniques".green
    $safe = true
  elsif !opts[:all] && opts[:safe]
    puts "[+] Using safe obfuscation techniques".green
    $safe = true
  elsif opts[:all] && !opts[:safe]
    puts "[+] Using all obfuscation techniques".green
    $all = true
  elsif opts[:all] && opts[:safe]
    puts "[+] Using all obfuscation techniques".green
    $all = true
  end

  # Open given file and read content
  file = File.open(opts[:file])
  file_data = file.read
  file.close
  puts "[+] File: #{opts[:file]}\n".green

  # Open file using Windows encoding to prevent errors
  file_data = file_data.encode("UTF-8", "windows-1252", invalid: :replace, undef: :replace, replace: "?")

  current_time = Time.now.strftime("%H:%M:%S")
  puts "[*] Starting obfuscation process at #{current_time}".blue

  # Main logic workflow starts here
  if $safe
    $case_obfs = true
    file_data = obfuscate_safe(file_data)
  elsif $all
    $case_obfs = true
    file_data = obfuscate_all(file_data)
  else
    if opts[:case]
      $case_obfs = true
    else
      $case_obfs = false
    end

    if opts[:comments]
      file_data = obfuscate_comments(file_data)
    end

    #if opts[:strings]
      #file_data = obfuscate_strings(file_data)
    #end

    if opts[:vars]
      file_data = obfuscate_variables(file_data)
    end

    if opts[:funcs]
      file_data = obfuscate_functions(file_data)
    end

    if opts[:cmdlets]
      file_data = obfuscate_cmdlets(file_data)
    end

    if opts[:namespaces]
      file_data = obfuscate_namespaces(file_data)
    end

    if opts[:backticks]
      file_data = obfuscate_backticks(file_data)
    end

    if opts[:pipes]
      file_data = obfuscate_pipes(file_data)
    end

    if opts[:indentation]
      file_data = obfuscate_indentation(file_data)
    end

    if opts[:ips]
      file_data = obfuscate_ips(file_data)
    end

    if opts[:special]
      file_data = obfuscate_special_vars(file_data)
    end

  end

  # Write obfuscated script to given file
  write_content(file_data, opts[:output])
  puts "\n[+] Obfuscated script written to #{opts[:output]}".green
end

main()

