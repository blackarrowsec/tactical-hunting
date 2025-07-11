# Hunt for WebDAV search-ms abuse on endpoint



## Sigma rules

### WEBDAV COOKIE PROCESS
```yaml
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: 'davclnt.dll,DavSetCookie'
  filter_domain_or_ip:
    CommandLine|regex: 
      - 'https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
      - 'https?:\/\/(\d{1,3}\.){3}\d{1,3}'
  condition: selection and filter_domain_or_ip
falsepositives:
  - Legitimate use of WebDAV with valid domains or IPs
```

### WEBDAV FILE MOUNT POINT
```yaml
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetObject|regex: '\\Device\\Mup\\;WebDavRedirector\\.*\\DavWWWRoot\\.*'
  filter_domain_or_ip:
    TargetObject|regex: 
      - '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
      - '(\d{1,3}\.){3}\d{1,3}'
  condition: selection and filter_domain_or_ip
falsepositives:
  - Legitimate use of WebDAV with valid domains or IPs
```
