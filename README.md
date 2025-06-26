![image](https://github.com/user-attachments/assets/5c438272-4aee-4188-9f63-c7042bf23a5d)

| Flag               | Description                                               | Example                                        |
|--------------------|-----------------------------------------------------------|------------------------------------------------|
| `-list`            | List available network interfaces                         | `go run packet-sniffer.go -list`               |
| `-n <index>`       | Select interface by index number                          | `go run packet-sniffer.go -n 2`                |
| `-i <interface>`   | Select specific interface directly                        | `go run packet-sniffer.go -i eth0`             |
| `-f <filter>`      | Set BPF filter ( `tcp`, `udp`, `icmp`) | `go run packet-sniffer.go -f tcp`                                 |
| `-w <file.pcap>`   | Save captured packets to a PCAP file                      | `go run packet-sniffer.go -w data.pcap`        |
| `-rotate-size <MB>`| Rotate PCAP file after reaching specified size (MB)       | `go run packet-sniffer.go -w data.pcap -rotate-size 100` |
| `-csv <file.csv>`  | Export statistics to CSV file                             | `go run packet-sniffer.go -csv stats.csv`      |
| `-lp <file.lp>`    | Export statistics in Influx line-protocol format          | `go run packet-sniffer.go -lp influx.lp`       |

  
