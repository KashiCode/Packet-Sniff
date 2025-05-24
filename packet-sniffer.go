// live_sniffer.go – Step 4 (expanded, readable style)
// ======================================================
// Adds a `-f "<bpf expr>"` flag so you can limit the live capture
// with the same syntax as tcpdump/Wireshark.  All previous widgets
// remain: PPS/BPS gauges, protocol bar chart, and top‑source table.
//
// Examples
// --------
//   go run . -n 5                             # unfiltered, as before
//   go run . -n 5 -f "icmp"                   # just ICMP
//   go run . -n 5 -f "tcp port 443"           # only HTTPS
//   go run . -i "\\Device\\NPF_{GUID}" -f "udp and port 53"
//
// Controls inside the UI:  q = quit   p = pause/resume
// ------------------------------------------------------
package main

import (
    "flag"
    "fmt"
    "log"
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

// ────────────────────────────────
// Data structures
// ────────────────────────────────

type packetInfo struct {
    size  int    // bytes on the wire
    proto string // "TCP", "UDP", "ICMP", "Other"
    src   string // source IP (string because we only need it as a map key)
}

// kv is used for the top‑talker table.
type kv struct {
    key string
    val uint64
}

type statsSnapshot struct {
    pps  uint64
    bps  uint64

    tcp  uint64
    udp  uint64
    icmp uint64
    oth  uint64

    top []kv // top‑N source IPs this second
}

// ────────────────────────────────
// Packet helpers
// ────────────────────────────────

// analyse returns the protocol class and source IP (if any).
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
        src = "<non-IP>"
    }

    return
}

// ────────────────────────────────
// Main
// ────────────────────────────────

func main() {
    // ----- flags ------------------------------------------------------
    list   := flag.Bool("list", false, "list interfaces and exit")
    idx    := flag.Int("n", 0, "index from -list (1‑based)")
    iface  := flag.String("i", "", "exact device string (overrides -n)")
    filter := flag.String("f", "", "BPF filter, e.g. 'tcp port 80'")
    flag.Parse()

    // ----- list‑only mode -------------------------------------------
    if *list {
        listIfaces()
        return
    }

    // ----- interface resolution -------------------------------------
    dev := resolveDevice(*iface, *idx)

    // ----- open capture ---------------------------------------------
    handle, err := pcap.OpenLive(dev, 2000, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("pcap open error on %s: %v", dev, err)
    }
    defer handle.Close()

    if *filter != "" {
        if err := handle.SetBPFFilter(*filter); err != nil {
            log.Fatalf("invalid BPF filter: %v", err)
        }
        fmt.Printf("[+] BPF filter applied: %s\n", *filter)
    }

    fmt.Printf("[*] Capturing on %s – q:quit  p:pause…\n", dev)

    // ----- channels --------------------------------------------------
    pktCh  := make(chan packetInfo, 4000)
    statCh := make(chan statsSnapshot, 5)

    go capture(handle, pktCh)
    go aggregate(pktCh, statCh)

    // ----- termui initialisation ------------------------------------
    if err := ui.Init(); err != nil {
        log.Fatalf("termui init: %v", err)
    }
    defer ui.Close()

    // ----- build widgets --------------------------------------------
    gaugePPS := widgets.NewGauge()
    gaugePPS.Title = "Packets / sec"
    gaugePPS.SetRect(0, 0, 60, 3)

    gaugeBPS := widgets.NewGauge()
    gaugeBPS.Title = "Bytes / sec"
    gaugeBPS.SetRect(0, 3, 60, 6)

    bar := widgets.NewBarChart()
    bar.Title  = "Protocol mix (pps)"
    bar.Labels = []string{"TCP", "UDP", "ICMP", "Other"}
    bar.SetRect(0, 6, 60, 14)

    table := widgets.NewTable()
    table.Title = "Top source IPs (pps)"
    table.Rows  = [][]string{{"IP", "pps"}}
    table.SetRect(0, 14, 60, 24)

    ui.Render(gaugePPS, gaugeBPS, bar, table)

    // ----- event loop -----------------------------------------------
    paused := false
    sigs   := make(chan os.Signal, 1)
    signal.Notify(sigs, os.Interrupt)

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
            }

        case snap := <-statCh:
            if paused {
                continue
            }
            updateUI(gaugePPS, gaugeBPS, bar, table, snap)
            ui.Render(gaugePPS, gaugeBPS, bar, table)
        }
    }
}

// ────────────────────────────────
// UI update helper
// ────────────────────────────────

func updateUI(gPPS, gBPS *widgets.Gauge, bar *widgets.BarChart, table *widgets.Table, s statsSnapshot) {
    // Gauges -----------------------------------------------------------
    gPPS.Label   = fmt.Sprintf("%d pps", s.pps)
    gPPS.Percent = int(scale(s.pps, 10_000)) // 10k pps ⇒ 100 %

    kb := s.bps / 1024
    gBPS.Label   = fmt.Sprintf("%d KB/s", kb)
    gBPS.Percent = int(scale(kb, 100_000)) // 100 MB/s ⇒ 100 %

    // Bar chart -------------------------------------------------------
    bar.Data = []float64{
        float64(s.tcp),
        float64(s.udp),
        float64(s.icmp),
        float64(s.oth),
    }

    // Top‑source table -----------------------------------------------
    rows := [][]string{{"IP", "pps"}}
    for _, kv := range s.top {
        rows = append(rows, []string{kv.key, fmt.Sprintf("%d", kv.val)})
    }
    table.Rows = rows
}

// ────────────────────────────────
// Goroutines
// ────────────────────────────────

func capture(h *pcap.Handle, out chan<- packetInfo) {
    src := gopacket.NewPacketSource(h, h.LinkType())

    for pkt := range src.Packets() {
        proto, ip := analyse(pkt)
        out <- packetInfo{
            size:  len(pkt.Data()),
            proto: proto,
            src:   ip,
        }
    }
}

func aggregate(in <-chan packetInfo, out chan<- statsSnapshot) {
    var (
        pps, bps             uint64
        tcp, udp, icmp, oth  uint64
        topMap               = make(map[string]uint64)
        ticker               = time.NewTicker(time.Second)
    )

    for {
        select {
        case p := <-in:
            // live counters
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
            // emit snapshot
            out <- statsSnapshot{
                pps:  pps,
                bps:  bps,
                tcp:  tcp,
                udp:  udp,
                icmp: icmp,
                oth:  oth,
                top:  topN(topMap, 5),
            }

            // reset counters
            pps, bps, tcp, udp, icmp, oth = 0, 0, 0, 0, 0, 0
            topMap = make(map[string]uint64)
        }
    }
}

// ────────────────────────────────
// Utility functions
// ────────────────────────────────

// listIfaces prints the capture interfaces with an index number.
func listIfaces() {
    devs, _ := pcap.FindAllDevs()

    fmt.Println("Capture interfaces:")
    for i, d := range devs {
        desc := d.Description
        if desc == "" {
            desc = d.Name
        }
        fmt.Printf("%2d. %-45s (%s)\n", i+1, d.Name, desc)
    }
}

// resolveDevice picks the interface to capture on based on -i or -n.
func resolveDevice(custom string, idx int) string {
    if custom != "" {
        return custom
    }

    devs, _ := pcap.FindAllDevs()

    if idx > 0 && idx <= len(devs) {
        return devs[idx-1].Name
    }

    // else: first non‑loopback
    for _, d := range devs {
        low := strings.ToLower(d.Name + d.Description)
        if strings.Contains(low, "loopback") || strings.HasPrefix(low, "lo") {
            continue
        }
        return d.Name
    }

    // fallback
    return devs[0].Name
}

// scale converts a value into a 0‑100 percentage relative to max.
func scale(val, max uint64) uint64 {
    if val >= max {
        return 100
    }
    return val * 100 / max
}

// topN returns the n largest entries of a string→uint64 map, sorted desc.
func topN(m map[string]uint64, n int) []kv {
    arr := make([]kv, 0, len(m))
    for k, v := range m {
        arr = append(arr, kv{key: k, val: v})
    }

        sort.Slice(arr, func(i, j int) bool {
        return arr[i].val > arr[j].val
    })

    if len(arr) > n {
        arr = arr[:n]
    }
    return arr
}