
package main

import (
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "sort"
    "strings"
    "time"

    ui "github.com/gizak/termui/v3"
    "github.com/gizak/termui/v3/widgets"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// ── data structures ───────────────────────────────────────

type packetInfo struct {
    size  int
    proto string // TCP / UDP / ICMP / Other
    src   string 
}

type statsSnapshot struct {
    pps  uint64
    bps  uint64
    tcp  uint64
    udp  uint64
    icmp uint64
    oth  uint64
    top  []kv 
}

type kv struct{
    key string
    val uint64
}


func analyse(pkt gopacket.Packet) (proto string, src string) {

    switch {
    case pkt.Layer(layers.LayerTypeTCP) != nil:
        proto = "TCP"
    case pkt.Layer(layers.LayerTypeUDP) != nil:
        proto = "UDP"
    case pkt.Layer(layers.LayerTypeICMPv4) != nil || pkt.Layer(layers.LayerTypeICMPv6) != nil:
        proto = "ICMP"
    default:
        proto = "Other"
    }

    if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
        src = ip4.(*layers.IPv4).SrcIP.String()
    } else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
        src = ip6.(*layers.IPv6).SrcIP.String()
    } else {
        src = "<non‑IP>"
    }
    return
}


func main() {
    list := flag.Bool("list", false, "list interfaces and exit")
    idx := flag.Int("n", 0, "index from -list (1-based)")
    iface := flag.String("i", "", "exact device string (overrides -n)")
    flag.Parse()

    if *list {
        listIfaces()
        return
    }
    dev := resolveDevice(*iface, *idx)

    h, err := pcap.OpenLive(dev, 2000, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("pcap open error on %s: %v", dev, err)
    }
    defer h.Close()

    fmt.Printf("[*] Capturing on %s – q=quit, p=pause…\n", dev)


    pktCh := make(chan packetInfo, 2000)
    statCh := make(chan statsSnapshot, 5)

    go capture(h, pktCh)
    go aggregate(pktCh, statCh)


    if err := ui.Init(); err != nil {
        log.Fatalf("termui init: %v", err)
    }
    defer ui.Close()

    gaugePPS := widgets.NewGauge()
    gaugePPS.Title = "Packets / sec"
    gaugePPS.SetRect(0, 0, 60, 3)

    gaugeBPS := widgets.NewGauge()
    gaugeBPS.Title = "Bytes / sec"
    gaugeBPS.SetRect(0, 3, 60, 6)

    bar := widgets.NewBarChart()
    bar.Title = "Protocol mix (pps)"
    bar.Labels = []string{"TCP", "UDP", "ICMP", "Other"}
    bar.SetRect(0, 6, 60, 14)

    table := widgets.NewTable()
    table.Title = "Top source IPs (pps)"
    table.Rows = [][]string{{"IP", "pps"}}
    table.SetRect(0, 14, 60, 24)

    ui.Render(gaugePPS, gaugeBPS, bar, table)

    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, os.Interrupt)

    paused := false
    events := ui.PollEvents()

    for {
        select {
        case <-sigs:
            return
        case e := <-events:
            switch e.ID {
            case "q", "Q", "<C-c>":
                return
            case "p", "P":
                paused = !paused
            }
        case s := <-statCh:
            if paused {
                continue
            }
      
            gaugePPS.Label = fmt.Sprintf("%d pps", s.pps)
            gaugePPS.Percent = int(scale(s.pps, 10000))
            kb := s.bps / 1024
            gaugeBPS.Label = fmt.Sprintf("%d KB/s", kb)
            gaugeBPS.Percent = int(scale(kb, 100000))
         
            bar.Data = []float64{float64(s.tcp), float64(s.udp), float64(s.icmp), float64(s.oth)}
         
            rows := [][]string{{"IP", "pps"}}
            for _, kv := range s.top {
                rows = append(rows, []string{kv.key, fmt.Sprintf("%d", kv.val)})
            }
            table.Rows = rows
            ui.Render(gaugePPS, gaugeBPS, bar, table)
        }
    }
}


func capture(h *pcap.Handle, out chan<- packetInfo) {
    src := gopacket.NewPacketSource(h, h.LinkType())
    for p := range src.Packets() {
        proto, ip := analyse(p)
        out <- packetInfo{size: len(p.Data()), proto: proto, src: ip}
    }
}

func aggregate(in <-chan packetInfo, out chan<- statsSnapshot) {
    var pps, bps uint64
    var tcp, udp, icmp, oth uint64
    topMap := make(map[string]uint64)

    ticker := time.NewTicker(time.Second)
    for {
        select {
        case p := <-in:
            pps++
            bps += uint64(p.size)
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
            topMap[p.src]++
        case <-ticker.C:
            out <- statsSnapshot{
                pps: pps, bps: bps,
                tcp: tcp, udp: udp, icmp: icmp, oth: oth,
                top: topN(topMap, 5),
            }
            // reset
            pps, bps, tcp, udp, icmp, oth = 0, 0, 0, 0, 0, 0
            topMap = make(map[string]uint64)
        }
    }
}


func listIfaces() {
    ifs, _ := pcap.FindAllDevs()
    fmt.Println("Capture interfaces:")
    for i, d := range ifs {
        desc := d.Description
        if desc == "" {
            desc = d.Name
        }
        fmt.Printf("%2d. %-45s (%s)\n", i+1, d.Name, desc)
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

func scale(val, max uint64) uint64 {
    if val >= max {
        return 100
    }
    return val * 100 / max
}

func topN(m map[string]uint64, n int) []kv {
    arr := make([]kv, 0, len(m))
    for k, v := range m {
        arr = append(arr, kv{k, v})
    }
    sort.Slice(arr, func(i, j int) bool { return arr[i].val > arr[j].val })
    if len(arr) > n {
        return arr[:n]
    }
    return arr
}
