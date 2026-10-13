<#
.SYNOPSIS
  NetBooty helper for Windows: one-shot boot requests and keeping NetBooty
  first in the firmware boot order.

.DESCRIPTION
  Run from an elevated PowerShell (Run as administrator).

    .\netbooty.ps1 status              Boot order, entries and any pending request
    .\netbooty.ps1 next <target>       Boot <target> (e.g. linux) once on the next boot
    .\netbooty.ps1 next clear          Cancel a pending request
    .\netbooty.ps1 reassert            Move NetBooty back to the front of the boot order
    .\netbooty.ps1 install-task        Run 'reassert' at every startup (after Windows Update
                                       moves Windows Boot Manager first)
    .\netbooty.ps1 uninstall-task      Remove that scheduled task

  Uses the UEFI variable API directly (no bcdedit parsing), so it works on any
  Windows language.
#>
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('status', 'next', 'reassert', 'install-task', 'uninstall-task')]
    [string]$Command,
    [Parameter(Position = 1)]
    [string]$Target
)

$ErrorActionPreference = 'Stop'

$GlobalGuid = '{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}'
$NetBootyGuid = '{6ADAECA3-9D97-4B60-90A8-A9F2D55969E1}'
$NvBsRt = 7
$EntryLabel = 'NetBooty'
$TaskName = 'NetBooty boot order'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class NbFirmware {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFirmwareEnvironmentVariableExW(string name, string guid, byte[] buf, uint size, out uint attrs);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool SetFirmwareEnvironmentVariableExW(string name, string guid, byte[] buf, uint size, uint attrs);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValueW(string system, string name, out long luid);
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct TokenPrivileges { public uint Count; public long Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state, uint len, IntPtr prev, IntPtr retLen);

    // Reading and writing UEFI variables needs SeSystemEnvironmentPrivilege,
    // which administrators have but must enable explicitly.
    public static void EnablePrivilege() {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Win32Exception();
        TokenPrivileges tp = new TokenPrivileges();
        tp.Count = 1;
        tp.Attributes = 2; // SE_PRIVILEGE_ENABLED
        if (!LookupPrivilegeValueW(null, "SeSystemEnvironmentPrivilege", out tp.Luid)) throw new Win32Exception();
        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (err != 0) throw new Win32Exception(err, "could not enable SeSystemEnvironmentPrivilege (run as administrator)");
    }

    // Returns null when the variable does not exist.
    public static byte[] Get(string name, string guid) {
        byte[] buf = new byte[8192];
        uint attrs;
        uint n = GetFirmwareEnvironmentVariableExW(name, guid, buf, (uint)buf.Length, out attrs);
        if (n == 0) {
            int err = Marshal.GetLastWin32Error();
            if (err == 203) return null; // ERROR_ENVVAR_NOT_FOUND
            throw new Win32Exception(err);
        }
        Array.Resize(ref buf, (int)n);
        return buf;
    }

    // An empty value deletes the variable.
    public static void Set(string name, string guid, byte[] data, uint attrs) {
        uint len = data == null ? 0u : (uint)data.Length;
        if (!SetFirmwareEnvironmentVariableExW(name, guid, data, len, attrs)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@

function Assert-Admin {
    $id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell (Run as administrator).'
    }
    [NbFirmware]::EnablePrivilege()
}

function Get-BootOrder {
    $raw = [NbFirmware]::Get('BootOrder', $GlobalGuid)
    if (-not $raw) { return @() }
    $order = @()
    for ($i = 0; $i + 1 -lt $raw.Length; $i += 2) { $order += [BitConverter]::ToUInt16($raw, $i) }
    return $order
}

function Set-BootOrder([uint16[]]$Order) {
    $bytes = New-Object byte[] ($Order.Length * 2)
    for ($i = 0; $i -lt $Order.Length; $i++) {
        [BitConverter]::GetBytes($Order[$i]).CopyTo($bytes, $i * 2)
    }
    [NbFirmware]::Set('BootOrder', $GlobalGuid, $bytes, $NvBsRt)
}

# Description of Boot####: UTF-16 string after the 4-byte attributes and
# 2-byte device path length.
function Get-EntryDescription([uint16]$Num) {
    $raw = [NbFirmware]::Get(('Boot{0:X4}' -f $Num), $GlobalGuid)
    if (-not $raw -or $raw.Length -lt 8) { return $null }
    $end = 6
    while ($end + 1 -lt $raw.Length -and ($raw[$end] -ne 0 -or $raw[$end + 1] -ne 0)) { $end += 2 }
    return [Text.Encoding]::Unicode.GetString($raw, 6, $end - 6)
}

function Find-NetBootyEntry {
    $candidates = @(Get-BootOrder) + (0..255)
    foreach ($n in ($candidates | Select-Object -Unique)) {
        if ((Get-EntryDescription $n) -eq $EntryLabel) { return [uint16]$n }
    }
    return $null
}

function Get-Pending {
    $raw = [NbFirmware]::Get('NetBootyNext', $NetBootyGuid)
    if (-not $raw) { return $null }
    return ([Text.Encoding]::ASCII.GetString($raw)).TrimEnd([char]0)
}

switch ($Command) {
    'status' {
        Assert-Admin
        $current = [NbFirmware]::Get('BootCurrent', $GlobalGuid)
        if ($current) { 'BootCurrent: Boot{0:X4}' -f [BitConverter]::ToUInt16($current, 0) }
        'Boot order:'
        foreach ($n in Get-BootOrder) { '  Boot{0:X4}  {1}' -f $n, (Get-EntryDescription $n) }
        $pending = Get-Pending
        if ($pending) { "Next boot (NetBootyNext): $pending" }
    }
    'next' {
        if (-not $Target) { throw 'usage: netbooty.ps1 next <target>|clear' }
        Assert-Admin
        if ($Target -eq 'clear') {
            if (Get-Pending) { [NbFirmware]::Set('NetBootyNext', $NetBootyGuid, $null, $NvBsRt) }
            'Cleared the pending request.'
        } else {
            if ($Target -notmatch '^[A-Za-z0-9._-]{1,15}$') { throw "invalid target name '$Target'" }
            $bytes = New-Object byte[] 16
            [Text.Encoding]::ASCII.GetBytes($Target).CopyTo($bytes, 0)
            [NbFirmware]::Set('NetBootyNext', $NetBootyGuid, $bytes, $NvBsRt)
            "NetBooty will boot '$Target' on the next boot."
        }
    }
    'reassert' {
        Assert-Admin
        $nb = Find-NetBootyEntry
        if ($null -eq $nb) { throw "no '$EntryLabel' boot entry found; install NetBooty from Linux first" }
        $order = @(Get-BootOrder)
        if ($order.Length -gt 0 -and $order[0] -eq $nb) {
            'NetBooty is already first.'
        } else {
            Set-BootOrder (@($nb) + @($order | Where-Object { $_ -ne $nb }))
            'Moved NetBooty (Boot{0:X4}) to the front of the boot order.' -f $nb
        }
    }
    'install-task' {
        Assert-Admin
        $dir = Join-Path $env:ProgramData 'NetBooty'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $script = Join-Path $dir 'netbooty.ps1'
        Copy-Item -Force $PSCommandPath $script
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" reassert"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        "Installed scheduled task '$TaskName' (runs $script reassert at startup)."
    }
    'uninstall-task' {
        Assert-Admin
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        $dir = Join-Path $env:ProgramData 'NetBooty'
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        "Removed scheduled task '$TaskName'."
    }
}
