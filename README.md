# YDConfig

iCLI utility to configure Yacht Devices devices from Raspberry Pi CLI. Should work on any SocketCAN systemc though.

## Usage example

```
ydconfig --list
Claiming NMEA 2000 source address...
YDTC-13 SW:Digital Thermometer / YACHTD.COM SN:01031080 - CAN Address: 52
YDTC-13 SW:Digital Thermometer / YACHTD.COM SN:01031078 - CAN Address: 116

ydconfig --dest 52 --command "YD:DEV 1"
```