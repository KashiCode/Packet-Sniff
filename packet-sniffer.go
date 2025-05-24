
package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

func main() {
    list := flag.Bool("list", false, "list available interfaces and exit")
    index := flag.Int("n", 0, "index of interface from -list (1-based)")
    iface := flag.String("i", "", "exact device string to sniff (overrides -n)")
    dur := flag.Int("d", 15, "capture duration in seconds (0 = unlimited)")
    flag.Parse()

    devs, err := pcap.FindAllDevs()
    if err != nil || len(devs) == 0 {
        log.Fatalf("could not list interfaces: %v", err)
    }

    if *list {
        fmt.Println("Available capture interfaces:")
        for idx, d := range devs {
            friendly := d.Description
            if friendly == "" {
                friendly = d.Name
            }
            fmt.Printf("%2d. %-40s (%s)\n", idx+1, d.Name, friendly)
        }
        fmt.Println("Use -n <index> or -i <device> to capture.")
        return
    }

   
    var device string
    if *iface != "" {
        device = *iface
    } else if *index > 0 && *index <= len(devs) {
        device = devs[*index-1].Name
    } else {
     
        for _, d := range devs {
            low := strings.ToLower(d.Name + d.Description)
            if strings.Contains(low, "loopback") || strings.HasPrefix(low, "lo") {
                continue
            }
            device = d.Name
            break
        }
        if device == "" {
            device = devs[0].Name
        }
    }

    
    handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("pcap open error on %s: %v", device, err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packets := packetSource.Packets()

    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, os.Interrupt)

    fmt.Printf("[*] Sniffing on %s for %d seconds…\n", device, *dur)
    start := time.Now()
    nextReport := start.Add(time.Second)
    var total uint64

    done := false
    for !done {
        select {
        case <-sigs:
            fmt.Println("\nInterrupt – stopping capture…")
            done = true
        case _, ok := <-packets:
            if !ok {
                done = true
                break
            }
            total++
        case <-time.After(25 * time.Millisecond):
            
        }
        if time.Now().After(nextReport) {
            fmt.Printf("[+] %ds – packets captured: %d\n", int(time.Since(start).Seconds()), total)
            nextReport = nextReport.Add(time.Second)
        }
        if *dur > 0 && time.Since(start) >= time.Duration(*dur)*time.Second {
            done = true
        }
    }
    fmt.Printf("Done. Captured %d packets.\n", total)
}