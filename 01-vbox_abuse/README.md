# VirtualBox abuse to execute malicious VMs

(th_1-1.png)
(th_1-2.png)

## Sigma rules

### Execution from suspicious location
```yaml
detection:
  selection_img:
    - Image|endswith: '\vboxheadless.exe'
  selection_cli:
    - CommandLine|re: '–startvm|-s '
  filter_legit_location:
    Image|contains:
      - ':\Program Files\Oracle\VirtualBox\'
      - ':\Program Files (x86)\Oracle\VirtualBox\'
  condition: all of selection_* and not 1 of filter_*
```

### Execution from suspicious parent
```yaml
detection:
  selection_img:
    - Image|endswith: '\vboxheadless.exe'
  selection_cli:
    - CommandLine|re: '–startvm|-s '
  filter_legit_parent:
    ParentImage|contains:
      - ':\Program Files\Oracle\VirtualBox\'
      - ':\Program Files (x86)\Oracle\VirtualBox\'
  condition: all of selection_* and not 1 of filter_*
```

### Execution from shell/script
```yaml
detection:
  selection_img:
    - Image|endswith: '\vboxheadless.exe'
  selection_cli:
    - CommandLine|re: '–startvm|-s '
  selection_susp_parent:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\powershell_ise.exe'
      - '\cscript.exe'
      - '\wscript.exe'
      - '\mshta.exe'
  condition: all of selection_*
```
