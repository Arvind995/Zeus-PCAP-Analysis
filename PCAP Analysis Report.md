#  Zeus PCAP Analysis Report

## 1. Project Overview
This project analyses a Zeus malware sample PCAP file using Wireshark.  
Goal: Demonstrate malware traffic analysis, DNS beaconing detection, HTTP communication review, and IOC extraction for a cybersecurity portfolio project.

---

## 2. Capture Overview
| Metric             | Value |
|--------------------|-------|
| Total Packets       | 122 |
| Duration            | 17389.99 seconds |
| Total Bytes         | 80 KB |
| Protocols Observed  | DNS, HTTP, TCP |
| Comments            | Low-volume traffic but long duration suggests beaconing or C2 communication |

---

## 3. DNS Analysis
| Observation | Details |
|-------------|---------|
| Domains Queried | The infected host sends repeated DNS queries to a suspicious-looking domain (example: randomstring.maliciousdomain.com). |
| Suspicious Domains | Domains with random strings or unknown TLDs (common with Zeus C2 infrastructure). |
| Notes | The DNS responses resolve to an external IP that could be a C2 server. Compare this IP with Threat Intelligence sources (VirusTotal, AbuseIPDB, etc.). |

**Screenshots:**
- `![DNS Queries](evidence/screenshots/DNS_queries.png)`

---

## 4. HTTP Analysis
| Observation | Details |
|-------------|---------|
| HTTP Methods | GET requests observed (no POST) |
| Suspicious URLs | GET /index.php repeatedly requested from the same server |
| User-Agent | Mozilla/4.0 (compatible; MSIE 8.0…) (outdated browser agent often used by malware) |
| Notes | Multiple GET requests to the same resource at regular intervals indicate potential beaconing or data exfiltration attempt. |

**Screenshots:**
- `![HTTP GET](evidence/screenshots/http_get_index_php.png)`

---

## 5. Conversations Analysis
| Host A (Infected) | Host B (Suspicious) | Packets | Bytes | Notes |
|-------------------|---------------------|---------|-------|-------|
| 192.168.0.250 | 205.251.133.247 | 122 | 80kb | Low volume, long duration conversation typical of malware beaconing. |

**Screenshots:**
- `![Conversations](evidence/screenshots/conversations.png)`

---

## 6. Beaconing Pattern
Evidence of repeated connections at regular intervals suggests beaconing.

**Steps Taken:**
- Used IO Graph with filter `ip.addr == 192.168.0.250 to see repeated spikes.
- Interval set to 10 seconds.

**Screenshot:**
- `![IO Graph](evidence/screenshots/io_graph.png)`

**Table Example:**

| Interval (sec) | Destination IP | Protocol | Notes |
|----------------|---------------|-----------|-------|
| Every 10 sec  | 205.251.133.247 | HTTP GET  | Repeated beaconing to /index.php |

---

## 7. Indicators of Compromise (IOCs)
| IOC Type   | Value (Example)                  | Notes |
|------------|---------------------------------|-------|
| Domain     | randomstring.maliciousdomain.com | Likely C2 domain queried by infected host |
| IP Address | 205.251.133.247                  | External server receiving repeated HTTP GETs |
| User-Agent | Mozilla/4.0 (compatible; MSIE 8.0) | Outdated User-Agent commonly associated with malware |

---

## 8. Conclusion
The Zeus PCAP shows:
- Repeated DNS queries to suspicious, random domains.
- HTTP GET requests to `/index.php` from an outdated User-Agent.
- Persistent low-volume communication consistent with malware beaconing.

---

## 9. Recommendations
- Block suspicious domains and IPs at the firewall.
- Quarantine the infected host for forensic investigation.
- Correlate IP/domain with threat intelligence feeds for confirmation.
- Implement intrusion detection signatures for repeated GET requests to /index.php or similar indicators.
- Train SOC analysts to look for beaconing patterns in low-volume, long-duration traffic.

---

## 10. Evidence Links
- [Screenshots Folder](./evidence/screenshots)
