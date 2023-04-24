# Vulkan

Offensive tool to create polymorphic FUD Powershell payloads

# Introduction

This tools is able to obfuscate and modify powershell code using some known techniques and creativity, however it may have some error so feel free to open an issue or a pull request. Most of the well known used Powershell payloads are detected by most of the AVs just by looking at the code. This tool makes all neccessary changes on the script to make it work as expected but without being detected by AVs. I would explain in deepth all the modifications and how obfuscation works but you can take a look at it [here](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/main/layer-0-obfuscation.md), it's a great explanation from ***gh0x0st***, the creator of [Invoke-PSObfuscation](https://github.com/gh0x0st/Invoke-PSObfuscation) so all credits to him

# Features

- All-in-one portable script
- Undetectable against AVs
- Pre-loaded Nishang payloads
- Replace functions and variables with random names
- Random combinations between uppercase and lowercase characters
- Integers obfuscation
- Add backticks
- Edit and remove comments
- Obfuscate strings with multiple techniques
- Obfuscate integers

# Payloads

Some Nishang payloads are pre-loaded and you don't have to download the script, you can simply generate a FUD payload on the fly:

```
Invoke-PowerShellTcp.ps1
Invoke-PowerShellUdp.ps1
Invoke-PowerShellTcpOneLine.ps1
Get-Information.ps1
Get-WLAN-Keys.ps1
Get-PassHashes.ps1
Get-LSASecret.ps1
Copy-VSS.ps1
Check-VM.ps1
Invoke-PortScan.ps1
Invoke-PsUACme.ps1
Remove-Update.ps1
Add-Persistence.ps1
Download.ps1
Parse_Keys.ps1
Invoke-AmsiBypass.ps1
```

# Usage

Clone the repo, move into it and then execute the `main.rb` script

```sh
git clone https://github.com/D3Ext/Vulkan
cd Vulkan
ruby main.rb
```

> Help panel
```

```

> Custom powershell script
```sh
ruby main.rb -f script.ps1 -o output.ps1
```

> Extreme obfuscation
```sh
ruby main.rb -p Invoke-ReverseShellTcp -o output.ps1 --extreme
```

> Custom amount of iterations
```sh
ruby main.rb -f script.ps1 -o output.ps1 -i 3
```

# Demo

<img src="">

<img src="">

<img src="">

# TODO

- Custom payloads
- More obfuscation avoiding errors

# References

```
https://amsi.fail
https://github.com/RythmStick/AMSITrigger
https://github.com/danielbohannon/Invoke-Obfuscation
https://github.com/samratashok/nishang
https://github.com/GetRektBoy724/BetterXencrypt
https://github.com/gh0x0st/Invoke-PSObfuscation
https://github.com/gh0x0st/Invoke-PSObfuscation/blob/main/layer-0-obfuscation.md
```

# Contributing

This tool may have errors so if you help with that it would be a great support, new features and changes are also welcome. I'm just one guy with this project so I'll try to reply you as quickly as possible

See [CONTRIBUTING.md]()

# Disclaimer

Use this project under your own responsability! The author is not responsible of any bad usage of the project.

# License

This project is licensed under MIT license

Copyright © 2023, D3Ext

<img src="">


