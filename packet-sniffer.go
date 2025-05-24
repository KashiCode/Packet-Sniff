

package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "strings"
    "sync/atomic"
    "time"

    ui "github.com/gizak/termui/v3"
    "github.com/gizak/termui/v3/widgets"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)



type packetInfo struct {
    size  int
    proto string // "TCP", "UDP", "ICMP", "Other"
}

type statsSnapshot struct {
    pps  uint64
    bps  uint64
    tcp  uint64
    udp  uint64
    icmp uint64
    oth  uint64
}


func classify(pkt gopacket.Packet) (proto string) {
    if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
        return "TCP"
    }
    if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
        return "UDP"
    }
    if l := pkt.Layer(layers.LayerTypeICMPv4); l != nil || pkt.Layer(layers.LayerTypeICMPv6) != nil {
        return "ICMP"
    }
    return "Other"
}


func main() {
    list := flag.Bool("list", false, "list interfaces and exit")
    index := flag.Int("n", 0, "index from -list (1‑based)")
    iface := flag.String("i", "", "exact device string to sniff (overrides -n)")
    flag.Parse()

    
    if *list {
        ifs, err := pcap.FindAllDevs()
        if err != nil {
            log.Fatalf("could not list interfaces: %v", err)
        }
        fmt.Println("Capture interfaces:")
        for i, d := range ifs {
            desc := d.Description
            if desc == "" {
                desc = d.Name
            }
            fmt.Printf("%2d. %-45s (%s)\n", i+1, d.Name, desc)
        }
        return
    }

    device := resolveDevice(*iface, *index)

    handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("pcap open error on %s: %v", device, err)
    }
    defer handle.Close()

    fmt.Printf("[*] Capturing on %s – press q to quit, p to pause…\n", device)

    
    pktCh := make(chan packetInfo, 1000)
    statCh := make(chan statsSnapshot, 10)

    
    go captureLoop(handle, pktCh)
    go statsLoop(pktCh, statCh)

    
    if err := ui.Init(); err != nil {
        log.Fatalf("termui init: %v", err)
    }
    defer ui.Close()

    gaugePPS := widgets.NewGauge()
    gaugePPS.Title = "Packets / sec"
    gaugePPS.SetRect(0, 0, 50, 3)

    gaugeBPS := widgets.NewGauge()
    gaugeBPS.Title = "Bytes / sec"
    gaugeBPS.SetRect(0, 3, 50, 6)

    bar := widgets.NewBarChart()
    bar.Title = "Protocol mix (pps)"
    bar.Labels = []string{"TCP", "UDP", "ICMP", "Other"}
    bar.SetRect(0, 6, 50, 14)

    ui.Render(gaugePPS, gaugeBPS, bar)

  
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, os.Interrupt)

    paused := false

    uiEvents := ui.PollEvents()
    for {
        select {
        case <-sigs:
            return
        case e := <-uiEvents:
            switch e.ID {
            case "q", "Q", "<C-c>":
                return
            case "p", "P":
                paused = !paused
                if paused {
                    gaugePPS.Title = "Packets / sec (paused)"
                } else {
                    gaugePPS.Title = "Packets / sec"
                }
            }
        case s := <-statCh:
            if paused {
                continue
            }
            gaugePPS.Percent = int(min(s.pps, 10000) * 100 / 10000) 
            gaugePPS.Label = fmt.Sprintf("%d pps", s.pps)

            kb := s.bps / 1024
            gaugeBPS.Percent = int(min(kb, 100000) * 100 / 100000) 
            gaugeBPS.Label = fmt.Sprintf("%d KB/s", kb)

            bar.Data = []float64{float64(s.tcp), float64(s.udp), float64(s.icmp), float64(s.oth)}

            ui.Render(gaugePPS, gaugeBPS, bar)
        }
    }
}


func captureLoop(handle *pcap.Handle, out chan<- packetInfo) {
    src := gopacket.NewPacketSource(handle, handle.LinkType())
    for pkt := range src.Packets() {
        out <- packetInfo{size: len(pkt.Data()), proto: classify(pkt)}
    }
}

func statsLoop(in <-chan packetInfo, out chan<- statsSnapshot) {
    var totPackets, totBytes uint64
    var tcp, udp, icmp, oth uint64

    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()

    for {
        select {
        case p := <-in:
            totPackets++
            totBytes += uint64(p.size)
            switch p.proto {
            case "TCP":
                tcp++
            case "UDP":
                udp++
            case "ICMP":
                icmp++
            default:
                oth++
            }
        case <-ticker.C:
            out <- statsSnapshot{pps: totPackets, bps: totBytes, tcp: tcp, udp: udp, icmp: icmp, oth: oth}
            atomic.StoreUint64(&totPackets, 0)
            atomic.StoreUint64(&totBytes, 0)
            tcp, udp, icmp, oth = 0, 0, 0, 0
        }
    }
}


func resolveDevice(custom string, idx int) string {
    if custom != "" {
        return custom
    }
    devs, _ := pcap.FindAllDevs()
    if idx > 0 && idx <= len(devs) {
        return devs[idx-1].Name
    }
   
    for _, d := range devs {
        low := strings.ToLower(d.Name + d.Description)
        if strings.Contains(low, "loopback") || strings.HasPrefix(low, "lo") {
            continue
        }
        return d.Name
    }
    return devs[0].Name
}

func min(a, b uint64) uint64 {
    if a < b {
        return a
    }
    return b
}
