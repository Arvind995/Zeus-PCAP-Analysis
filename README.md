# Zeus-PCAP-Analysis

 ##  ****Summary****:
This repository contains a beginner-level network traffic analysis project using Wireshark on a Zeus PCAP malware sample. The analysis demonstrates the ability to identify suspicious DNS and HTTP traffic patterns, document indicators of compromise (IOCs) and interpret malware beaconing behaviour.

****Environment****: Kali Linux, Wireshark GUI

****Source****: Zeus PCAP file(not disclosed for secuirty reasons)

# Capture Overview:
- ****Packets****: 122

- ****Duration****: 17389.99 seconds (~4 hours 50 minutes)

- ****Total Bytes****: ~80 KB

- ****Protocols Observed****: HTTP, DNS, TCP

- ****Comments****: Repeated GET requests to a suspicious domain indicate automated beaconing behavior.

#  HTTP Analysis (GET Requests):

- ****Suspicious GET request****: /index.php

- ****Host****: claimfans.com\r\n

- ****Source IP****: 192.168.0.251

- ****Destination IP****: 205.251.133.247

- ****User-Agent****: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)

- ****Pattern****: Repeated GETs at regular intervals (~2–3 minutes), typical of beaconing.

- ****Payload****: Encoded / unreadable in query parameters

# Evidence:
Screenshot: evidence/screenshots/http_get_index_php.png

CSV Export: evidence/http_get_requests.csv

HTTP Stream (optional): evidence/http_stream_frame23.txt

Red Flags Observed: GET requests to unusual domain and URI, repeated automated pattern, old/fake User-Agent.

 # Conversations:

- ****Infected Host****: 192.168.0.251

- ****C2 Server****: 205.251.133.247

- ****Packets****: 122

- ****Bytes****: 80 KB

 # Beaconing Pattern:

- ****Observation****: Periodic spikes in GET requests over the capture duration (~4 hours 50 minutes) confirm automated beaconing.
- ****Evidence****: Screenshot: evidence/screenshots/io_graph.png

# IOC Table:

 | IOC Type     | Value                  | Notes                        |
|--------------|------------------------|------------------------------|
| Domain       |    claimfans.com\r\n    |   C2 Server                 |
| IP Address   | 192.168.0.251           | Internal host infected       |
| User-Agent   | Mozilla/4.0 (MSIE 8.0)  | Suspicious old browser agent |

 # Recommended Actions:

 - Block domain/IP at network perimeter

 - Isolate infected host

 - Investigate endpoint for persistence (registry keys, scheduled tasks)

 - Submit payloads or domain/IP to VirusTotal for confirmation
