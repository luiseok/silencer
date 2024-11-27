# silencer

> Originated by [EDRSilencer](https://github.com/netero1010/EDRSilencer)

A tool that blocks outbound network traffic for specific processes using Windows Filtering Platform (WFP) APIs.

## Features
- Block outbound traffic for a process by PID
- Remove all WFP filters created by this tool
- Remove a specific WFP filter by filter ID

## Testing Environment
Tested in Windows 10 and Windows Server 2016

## Usage
```
Usage: silencer.exe <block/unblockall/unblock>
- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process by ID (PID is required):
  silencer.exe block <PID>

- Remove all WFP filters applied by this tool:
  silencer.exe unblockall

- Remove a specific WFP filter based on filter id:
  silencer.exe unblock <filter id>
```

## Compile
```powershell
x86_64-w64-mingw32-gcc silencer.c utils.c -o silencer.exe -lfwpuclnt
```

## Example
### Detect and block the outbound traffic of running EDR processes
```powershell
silencer.exe block <PID> # ex) silencer.exe block 1234
```
## Credits
https://github.com/netero1010/EDRSilencer
https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/
