// live_sniffer.go 
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



type packetInfo struct {
	size  int
	proto string
	src   string
}

type kv struct {
	key string
	val uint64
}

type statsSnapshot struct {
	pps, bps             uint64
	tcp, udp, icmp, oth  uint64
	top                  []kv
}



func analyse(pkt gopacket.Packet) (proto, src string) {
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



func main() {
	list   := flag.Bool("list", false, "list interfaces and exit")
	idx    := flag.Int("n", 0,      "index from -list (1-based)")
	iface  := flag.String("i", "",  "exact device string (overrides -n)")
	filter := flag.String("f", "",  "BPF filter, e.g. 'tcp port 80'")
	flag.Parse()

	*filter = expandSimpleFilter(strings.Trim(*filter, "\"'"))

	if *list {
		listIfaces(); return
	}
	dev := resolveDevice(*iface, *idx)

	handle, err := pcap.OpenLive(dev, 2000, true, pcap.BlockForever)
	if err != nil { log.Fatalf("pcap open error on %s: %v", dev, err) }
	defer handle.Close()

	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatalf("invalid BPF filter: %v", err)
		}
		fmt.Printf("[+] BPF filter applied: %s\n", *filter)
	}

	fmt.Printf("[*] Capturing on %s  –  q quit | p pause …\n", dev)

	/* channels */
	pktCh  := make(chan packetInfo, 4096)
	statCh := make(chan statsSnapshot, 8)

	go capture(handle, pktCh)
	go aggregate(pktCh, statCh)


	if err := ui.Init(); err != nil { log.Fatalf("termui init: %v", err) }
	defer ui.Close()

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

	paused := false
	sigs   := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	uiEvents := ui.PollEvents()
	uiTick   := time.NewTicker(500 * time.Millisecond) 
	defer uiTick.Stop()

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
			if paused { continue }
			updateUI(gaugePPS, gaugeBPS, bar, table, snap)
			ui.Render(gaugePPS, gaugeBPS, bar, table)

		case <-uiTick.C:
			if !paused {
				ui.Render(gaugePPS, gaugeBPS, bar, table)
			}
		}
	}
}



func updateUI(gPPS, gBPS *widgets.Gauge, bar *widgets.BarChart, table *widgets.Table, s statsSnapshot) {
	gPPS.Label   = fmt.Sprintf("%d pps", s.pps)
	gPPS.Percent = int(scale(s.pps, 10_000))

	kb := s.bps / 1024
	gBPS.Label   = fmt.Sprintf("%d KB/s", kb)
	gBPS.Percent = int(scale(kb, 100_000))

	bar.Data = []float64{float64(s.tcp), float64(s.udp), float64(s.icmp), float64(s.oth)}

	rows := [][]string{{"IP", "pps"}}
	for _, kv := range s.top {
		rows = append(rows, []string{kv.key, fmt.Sprintf("%d", kv.val)})
	}
	table.Rows = rows
}



func capture(h *pcap.Handle, out chan<- packetInfo) {
	src := gopacket.NewPacketSource(h, h.LinkType())
	for pkt := range src.Packets() {
		proto, ip := analyse(pkt)
		out <- packetInfo{size: len(pkt.Data()), proto: proto, src: ip}
	}
}

func aggregate(in <-chan packetInfo, out chan<- statsSnapshot) {
	var pps, bps, tcp, udp, icmp, oth uint64
	topMap := make(map[string]uint64)
	tick   := time.NewTicker(time.Second)

	for {
		select {
		case p := <-in:
			pps++
			bps += uint64(p.size)
			switch p.proto {
			case "TCP": tcp++
			case "UDP": udp++
			case "ICMP": icmp++
			default: oth++
			}
			topMap[p.src]++

		case <-tick.C:
			out <- statsSnapshot{pps, bps, tcp, udp, icmp, oth, topN(topMap, 5)}
			pps, bps, tcp, udp, icmp, oth = 0, 0, 0, 0, 0, 0
			topMap = make(map[string]uint64)
		}
	}
}



func listIfaces() {
	devs, _ := pcap.FindAllDevs()
	fmt.Println("Capture interfaces:")
	for i, d := range devs {
		desc := d.Description
		if desc == "" { desc = d.Name }
		fmt.Printf("%2d. %-45s (%s)\n", i+1, d.Name, desc)
	}
}

func resolveDevice(custom string, idx int) string {
	if custom != "" { return custom }
	devs, _ := pcap.FindAllDevs()
	if idx > 0 && idx <= len(devs) { return devs[idx-1].Name }
	for _, d := range devs {
		low := strings.ToLower(d.Name + d.Description)
		if strings.Contains(low, "loopback") || strings.HasPrefix(low, "lo") { continue }
		return d.Name
	}
	return devs[0].Name
}

func scale(val, max uint64) uint64 {
	if val >= max { return 100 }
	return val * 100 / max
}

func expandSimpleFilter(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "icmp":
		return "icmp"             
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	default:
		return s
	}
}

func topN(m map[string]uint64, n int) []kv {
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].val > arr[j].val })
	if len(arr) > n { arr = arr[:n] }
	return arr
}
