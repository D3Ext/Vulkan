<img src="assets/vulkan.webp">

# Vulkan

Offensive Powershell obfuscator

# Introduction

Vulkan is able to obfuscate powershell scripts in order to make them undetectable against antivirus solutions. To achieve so, Vulkan uses different techniques and tricks to manipulate powershell code (i.e. obfuscate variables, cmdlets, functions, etc). This tool is coded in Ruby and uses regular expressions to parse powershell code properly. Nishang payloads seem to work great after being obfuscated with this tool.

Warning: have in mind that this is not a professional tool and you may find errors

# Features

- All-in-one portable script
- Undetectable against AVs
- Malleable obfuscation configuration via CLI parameters
- Obfuscate variables
- Obfuscate functions
- Obfuscate cmdlets
- Obfuscate namespace classes
- Obfuscate comments
- Obfuscate IP addresses

And much more

# Usage

Clone the repo, move into it and then execute the `vulkan.rb` script

```sh
git clone https://github.com/D3Ext/Vulkan
cd Vulkan
gem install colorize httparty optparse
ruby vulkan.rb
```

> Help panel
```
╦  ╦┬ ┬┬  ┬┌─┌─┐┌┐┌
╚╗╔╝│ ││  ├┴┐├─┤│││
 ╚╝ └─┘┴─┘┴ ┴┴ ┴┘└┘
    by D3Ext v0.2

Usage of Vulkan:
  REQUIRED ARGUMENTS:
    -f, --file string     source Powershell script to obfuscate
    -o, --output string   store obfuscated script in a file

  OPTIONAL ARGUMENTS:
    -a, --all       use all obfuscation techniques
    -s, --safe      enable safe obfuscation mode to prevent the script from breaking (use almost all obfuscation techniques) (enabled by default)
    --vars          enable variable obfuscation
    --funcs         enable functions obfuscation
    --cmdlets       enable cmdlets obfuscation
    --namespaces    enable namespace classes obfuscation
    --backticks     enable backticks obfuscation
    --case          enable uppercase/lowercase obfuscation
    --pipes         enable pipes and pipelines obfuscation
    --comments      remove and obfuscate comments
    --indentation   add random indentation
    --ips           obfuscate IP adddresses by converting them to hex format

  EXTRA:
    -v, --verbose   enable verbose
    -d, --debug     enable debug mode to check how obfuscation works
    -h, --help      show help panel
    --about         show information about how to use this tool

Examples:
  vulkan.rb -f script.ps1 -o output.ps1 --verbose
  vulkan.rb -f script.ps1 -o output.ps1 --all
  vulkan.rb -f script.ps1 -o output.ps1 --vars --cmdlets
```

# Demo

<img src="https://raw.githubusercontent.com/D3Ext/Vulkan/main/assets/pic1.png">

<img src="https://raw.githubusercontent.com/D3Ext/Vulkan/main/assets/pic2.png">

# TODO

- Custom payloads
- More obfuscation

# References

```
https://amsi.fail
https://github.com/RythmStick/AMSITrigger
https://github.com/danielbohannon/Invoke-Obfuscation
https://github.com/samratashok/nishang
https://github.com/GetRektBoy724/BetterXencrypt
https://github.com/gh0x0st/Invoke-PSObfuscation
https://github.com/gh0x0st/Invoke-PSObfuscation/blob/main/layer-0-obfuscation.md
https://github.com/klezVirus/chameleon
https://github.com/CBHue/PyFuscation
```

# Contributing

This tool may contain errors so new features and changes are welcome. Feel free to open an issue or a PR

# Disclaimer

Use this project under your own responsability! The author is not responsible of any bad usage of the project.

# License

This project is licensed under MIT license

Copyright © 2024, D3Ext



