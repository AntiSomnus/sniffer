# Sniffer

Simple sniffer using scapy and wxpthon.

## Getting Started

Just download them all and run main.py

### Prerequisites

#### Use modified [scapy3k](https://github.com/phaethon/scapy)

Only test and modify the lib concerning Windows users.

Need to install [Win10Pcap(Recommended)](http://www.win10pcap.org/), Npcap(might have slight issue of missing certain packets).

#### GUI: PyQt5

#### Other libs: 

[PyShark](https://github.com/KimiNewt/pyshark) Used to parse packet to WireShark style brief information.	

[psutil](https://github.com/giampaolo/psutil) Used to detect packet received amount in system level to calculate network speed. 

### Usage
```
python main.py
```

## Feature

Multiple features in this project.

### Filter on Network interfaces, Protocol, Src, Dst, Sport and Dport.

Choose the filter anytime you like and then click the start button twice to continue sniffing.(have to stop and start to take effect)

### Save selected packet(s) information to files.

Select one packet, or use Ctrl+LeftClick to choose multiple packets. You can save them into a txt file with readable format.

### TCP/IP/HTTP reassembly and save them to files.

Select one packet, and it will automatically find related packets and reassemble them.
After that processing, you are welcome to click the `Reassembly` button to convert them into one entire file.
Only tested in FTP Transmission, HTML reassembly and ICMP(ping), and the file size can be up to 15MB (might take certain time processing to GUI)
New feature is added to show the whole size number after reassembly to have a quick peak of the whole process.

### Search bar makes things easier

Using search bar wisely can actually save a lot of time.
Keywords are searched in whole packet's hex or decoded by UTF-8 and GB2312,which is very convenient to find http headers of filename.

### MAX Module

The default MAX module will never let you down when an additional dedicated process is used for listening and sniffing.
However, it is very CPU-consuming, but you can turn it off any time (have to stop and start to take effect)

### Network Speed

The ultimate style of Network Speed uses the API of psutil which is extremely accurate and responsive.

### Brief Info like WireShark

As long as you pause in the middle of sniffing, using API of PyShark, the brief summary of each packet will show whenever you move your mouse cursor focus on it.
It is much convenient because you don't need to click and only moving mouse focus will help find the packet you are looking for.
Please notice that this feature will only take effect when you stop because it will otherwise reduce certain performance when sniffing. 


## Sample
### Sniffer v2.0:
![Sample](/sample.png "Sample")

