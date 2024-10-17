# nmap-scripts

## http-info.nse

Return status, title and favicon URL of a webpage

```lua
@args http-get.path Path to get. Default /.
@usage nmap -phttp,https --script http-info.nse --script-args http-info.path=/ <host>
@output
80/tcp   open   http
| http-info: 
|   status-line: HTTP/1.1 200 OK\x0D
| 
|   title: Go ahead and ScanMe!
|   favicon: http://scanme.nmap.org:80/shared/images/tiny-eyeicon.png
|_  status: 200
```

## smb-shares-size.nse

Return free and total size in octets of each SMB shares

```lua
@args See the documentation for the smbauth library.
@usage nmap -p137-139,445 --script smb-shares-size.nse --script-args-file smb-shares-size.ini <host>
@output
Host script results:
| smb-shares-size:
|   data:
|     FreeSize: 38495883264
|     TotalSize: 500961574912
|_  IPC$: NT_STATUS_ACCESS_DENIED
```
