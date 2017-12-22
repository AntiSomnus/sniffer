# Sniffer

Simple sniffer using scapy and PyQt5.
<!-- TOC -->

- [Sniffer](#sniffer)
    - [Getting Started](#getting-started)
        - [Prerequisites](#prerequisites)
        - [Optional](#optional)
    - [Usage](#usage)
    - [Feature](#feature)
        - [Filter on Network interfaces, Protocol, Src, Dst, Sport and Dport.](#filter-on-network-interfaces-protocol-src-dst-sport-and-dport)
        - [Save selected packet(s) information to files, and even copy to clipboard.](#save-selected-packets-information-to-files-and-even-copy-to-clipboard)
        - [TCP/IP/HTTP reassembly and save them to files.](#tcpiphttp-reassembly-and-save-them-to-files)
        - [Search bar makes things easier](#search-bar-makes-things-easier)
        - [OC Mode](#oc-mode)
        - [Network Speed](#network-speed)
        - [Color Theme like WireShark](#color-theme-like-wireshark)
        - [(Optional) Brief efficient information when mouse passes.](#optional-brief-efficient-information-when-mouse-passes)
    - [Summary](#summary)

<!-- /TOC -->
## Getting Started

Just download them all and run main.py

### Prerequisites

- Python 3.6
- Modified [scapy3k](https://github.com/phaethon/scapy) Used for multiprocessing purposes. Just use directly from here. 
- [ansi2html](https://github.com/ralphbean/ansi2html)  Used to parse ANSI ESCAPE Sequence to html css.
- [psutil](https://github.com/giampaolo/psutil)	Used to detect packet received amount in system level to calculate network speed. 
- [urllib3](https://github.com/shazow/urllib3)  Used to parse HTTP Response
- [PyQt5](https://riverbankcomputing.com/software/pyqt/download5) GUI
- Need to install [Win10Pcap(Recommended)](http://www.win10pcap.org/), Npcap(might have slight issue of missing certain packets).
Only test and modify the lib concerning Windows users.

### Optional
-  [pyshark](https://github.com/KimiNewt/pyshark) Used to parse brief infomation from raw packets.

   - Tips:
 
      However, the latest version works not well on Win10, so version 0.3.6.2 is only used and recommended if the the brief and efficient info for packet is what you need.

## Usage
```
pip install -r requirements.txt
python main.py

#Optional lib `pyshark` for parsing brief info from packet.
#pyshark version 0.3.6.2 is the only one that works an.
pip install pyshark==0.3.6.2
```

## Feature

Multiple features in this project.

### Filter on Network interfaces, Protocol, Src, Dst, Sport and Dport.

Choose the filter anytime you like and then click the start button twice to continue sniffing.(have to stop and start to take effect)

### Save selected packet(s) information to files, and even copy to clipboard.

Select one packet, or multiple packets. After using right clicks, you can save them into a txt file with readable format, or even copy
them into your clipboard(short-cut keys Ctrl-S,Ctrl-C). 

![Sample](/sample_pic/save_sample.gif "Sample")

### TCP/IP/HTTP reassembly and save them to files.

Select one packet, and it will automatically find related packets and reassemble them.
If the total fragments number is too big, it will give you the option to reassemble and decode it or not.
Remember that all the related fragments will be displayed immediately no matter what.
After that processing, you are welcome to click the `Reassembly` button below on the status to convert them into one entire file.
Only tested in FTP Transmission, HTML reassembly and ICMP(ping), and the file size can be up to 15MB (might take certain time processing to GUI).
New feature is added to show the whole size number after reassembly to have a quick peak of the whole process.

- sample of TCP/IP file saving Result:

![Sample](/sample_pic/reassemble_sample.gif "Sample")

- sample of HTTP(HTML) parsing Result:

![Sample](/sample_pic/html_sample.gif "HTML Sample")

### Search bar makes things easier

Using search bar wisely can actually save a lot of time.
Keywords are searched in whole packet's hex or decoded by UTF-8 and GB2312,which is very convenient to find http headers of filename.

### OC Mode

The default OC mode will never let you down when an additional dedicated process is used for listening and sniffing.
However, it is very CPU-consuming, but you can turn it off any time (have to stop and start to take effect)

### Network Speed

The ultimate style of Network Speed uses the API of psutil which is extremely accurate and responsive.


### Color Theme like WireShark

Every packet is sorted by the default color theme of wireshark. Default On. Using "Ctrl+F" to turn off/on.
ADD Mouse entering and leaving event for each row makes the UI more colorful and better.

### (Optional) Brief efficient information when mouse passes.

Thanks to the API of `pyshark`, the real information that contains a lot of useful details can be feeded whenever your mouse passes on. Remember it's only activated when `pyshark(version 0.3.6.2)` is installed and the current mode is `STOP`.


![Sample](/sample_pic/pyshark_sample.gif "HTML Sample")

## Summary


![Sample](/sample_pic/overall_sample.gif "Sample")

