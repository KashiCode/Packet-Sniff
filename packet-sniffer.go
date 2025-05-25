// live_sniffer.go – Full-featured TUI + CSV/LP + Rotation + Histogram + Dual Tables + Dynamic Resize
// ================================================================================================
// Flags:
//   -list              list interfaces and exit
//   -n <idx>           capture by index (1-based from -list)
//   -i <device>        capture by exact \\Device\\NPF_{GUID}
//   -f <expr>          BPF filter (quotes trimmed; icmp|tcp|udp shortcuts)
//   -w <file.pcap>     base name for PCAP dump
//   -rotate-size N     rotate PCAP every N MB (0=off)
//   -csv <file.csv>    write per-second stats to CSV
//   -lp <file.lp>      write per-second stats in Influx line-protocol
//
// TUI Keys:
//   p ↔ pause/resume    q or Ctrl-C → quit
//
// Layout auto‐scales to your full terminal size and reflows on resize.
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)



type packetInfo struct {
	size  int
	proto string
	src   string
	dst   string
}

type kv struct{ key string; val uint64 }

type statsSnapshot struct {
	pps, bps            uint64
	tcp, udp, icmp, oth uint64
	histogram           [4]uint64
	topSrc, topDst      []kv
}



func analyse(pkt gopacket.Packet) (proto, src, dst string) {
	switch {
	case pkt.Layer(layers.LayerTypeTCP) != nil:
		proto = "TCP"
	case pkt.Layer(layers.LayerTypeUDP) != nil:
		proto = "UDP"
	case pkt.Layer(layers.LayerTypeICMPv4) != nil ||
		pkt.Layer(layers.LayerTypeICMPv6) != nil:
		proto = "ICMP"
	default:
		proto = "Other"
	}
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		h := ip4.(*layers.IPv4)
		src, dst = h.SrcIP.String(), h.DstIP.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		h := ip6.(*layers.IPv6); src, dst = h.SrcIP.String(), h.DstIP.String()
	} else {
		src, dst = "<non-IP>", "<non-IP>"
	}
	return
}



func main() {

	list      := flag.Bool("list", false, "list interfaces and exit")
	idx       := flag.Int("n", 0, "index from -list (1-based)")
	iface     := flag.String("i", "", "exact device string (overrides -n)")
	filter    := flag.String("f", "", "BPF filter, e.g. 'tcp port 443'")
	outPC     := flag.String("w", "", "base name for PCAP dump")
	rotateMB  := flag.Int("rotate-size", 0, "rotate PCAP every N MB (0=off)")
	outCSV    := flag.String("csv", "", "write stats to <file.csv>")
	outLP     := flag.String("lp", "", "write stats in LP to <file.lp>")
	flag.Parse()
	*filter = expandSimpleFilter(strings.Trim(*filter, "\"'"))

	if *list {
		listIfaces()
		return
	}

	
	dev := resolveDevice(*iface, *idx)
	handle, err := pcap.OpenLive(dev, 2000, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap open %s: %v", dev, err)
	}
	defer handle.Close()

	
	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatalf("invalid BPF filter: %v", err)
		}
		fmt.Printf("[+] BPF filter applied: %s\n", *filter)
	}

	
	rotateBytes := int64(*rotateMB) * 1024 * 1024
	if *outPC != "" {
		if rotateBytes > 0 {
			fmt.Printf("[+] Rotating PCAP every %d MB, base=%s\n", *rotateMB, *outPC)
		} else {
			fmt.Printf("[+] Writing PCAP to %s\n", *outPC)
		}
	}

	
	var csvWriter *csv.Writer
	var csvFile *os.File
	if *outCSV != "" {
		f, err := os.Create(*outCSV)
		if err != nil {
			log.Fatalf("csv create: %v", err)
		}
		csvFile = f
		defer csvFile.Close() 
		csvWriter = csv.NewWriter(f)
		csvWriter.Write([]string{"time","pps","bps","tcp","udp","icmp","other"})
		csvWriter.Flush()
		fmt.Printf("[+] Writing CSV to %s\n", *outCSV)
	}

	
	var lpFile *os.File
	var lpWriter *bufio.Writer
	if *outLP != "" {
		f, err := os.Create(*outLP)
		if err != nil {
			log.Fatalf("lp create: %v", err)
		}
		lpFile = f
		defer lpFile.Close() 
		lpWriter = bufio.NewWriter(f)
		fmt.Printf("[+] Writing LP to %s\n", *outLP)
	}

	
	pktCh := make(chan packetInfo, 4096)
	statCh := make(chan statsSnapshot, 8)
	go capture(handle, *outPC, rotateBytes, handle.LinkType(), pktCh)
	go aggregate(pktCh, statCh)

	
	if err := ui.Init(); err != nil {
		log.Fatalf("termui init: %v", err)
	}
	defer ui.Close()


	gPPS := widgets.NewGauge()
	gBPS := widgets.NewGauge()
	bar  := widgets.NewBarChart()
	hist := widgets.NewBarChart()
	srcT := widgets.NewTable()
	dstT := widgets.NewTable()
	help := widgets.NewParagraph()
	help.Text = "[p] pause/resume   |   [q] quit"
	help.Border = false
	help.TextStyle = ui.NewStyle(ui.ColorYellow)

	
	w, h := ui.TerminalDimensions()
	layout(w, h, gPPS, gBPS, bar, hist, srcT, dstT, help)
	ui.Render(gPPS, gBPS, bar, hist, srcT, dstT, help)

	
	uiEvents := make(chan ui.Event, 20)
	go func() { for e := range ui.PollEvents() { uiEvents <- e } }()
	heartbeat := time.NewTicker(500 * time.Millisecond)
	defer heartbeat.Stop()

	paused := false
	sigCh  := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	for {
		select {
		case <-sigCh:
			return

		case e := <-uiEvents:
			switch e.ID {
			case "q","Q","<C-c>":
				return
			case "p","P":
				paused = !paused
			case "<Resize>":
				d := e.Payload.(ui.Resize)
				layout(d.Width, d.Height, gPPS, gBPS, bar, hist, srcT, dstT, help)
				ui.Clear()
				ui.Render(gPPS, gBPS, bar, hist, srcT, dstT, help)
			}

		case snap := <-statCh:
			
			if csvWriter != nil {
				csvWriter.Write([]string{
					time.Now().UTC().Format(time.RFC3339),
					strconv.FormatUint(snap.pps,10),
					strconv.FormatUint(snap.bps,10),
					strconv.FormatUint(snap.tcp,10),
					strconv.FormatUint(snap.udp,10),
					strconv.FormatUint(snap.icmp,10),
					strconv.FormatUint(snap.oth,10),
				})
				csvWriter.Flush()
			}
			
			if lpWriter != nil {
				ts := time.Now().UTC().UnixNano()
				lpWriter.WriteString(
					fmt.Sprintf("live_sniffer pps=%d,bps=%d,tcp=%d,udp=%d,icmp=%d,other=%d %d\n",
						snap.pps,snap.bps,snap.tcp,snap.udp,snap.icmp,snap.oth,ts))
				lpWriter.Flush()
			}
			if paused {
				continue
			}
			updateWidgets(snap, gPPS, gBPS, bar, hist, srcT, dstT)
			ui.Render(gPPS, gBPS, bar, hist, srcT, dstT, help)

		case <-heartbeat.C:
			if !paused {
				ui.Render(gPPS, gBPS, bar, hist, srcT, dstT, help)
			}
		}
	}
}



func layout(
	w, h int,
	gPPS, gBPS *widgets.Gauge,
	bar, hist *widgets.BarChart,
	srcT, dstT *widgets.Table,
	help *widgets.Paragraph,
) {
	
	gPPS.SetRect(0, 0, w, 3)
	gPPS.Title = "Packets / sec"
	gBPS.SetRect(0, 3, w, 6)
	gBPS.Title = "Bytes / sec"

	
	bar.SetRect(0, 6, w, 12)
	bar.Title  = "Protocol mix (pps)"
	bar.Labels = []string{"TCP","UDP","ICMP","Other"}

	
	hist.SetRect(0, 12, w, 16)
	hist.Title  = "Packet size histogram"
	hist.Labels = []string{"<=64B","65–512B","513–1500B",">1500B"}

	
	srcT.SetRect(0, 16, w/2, h-2)
	srcT.Title = "Top source IPs (pps)"
	srcT.Rows  = [][]string{{"IP","pps"}}

	dstT.SetRect(w/2, 16, w, h-2)
	dstT.Title = "Top destination IPs (pps)"
	dstT.Rows  = [][]string{{"IP","pps"}}

	
	help.SetRect(0, h-2, w, h)
}



func updateWidgets(
	s statsSnapshot,
	gPPS, gBPS *widgets.Gauge,
	bar, hist *widgets.BarChart,
	srcT, dstT *widgets.Table,
) {
	gPPS.Label, gPPS.Percent = fmt.Sprintf("%d pps", s.pps), int(scale(s.pps,10000))
	kb := s.bps / 1024
	gBPS.Label, gBPS.Percent = fmt.Sprintf("%d KB/s", kb), int(scale(kb,100000))

	bar.Data = []float64{
		float64(s.tcp), float64(s.udp),
		float64(s.icmp), float64(s.oth),
	}

	hist.Data = []float64{
		float64(s.histogram[0]),
		float64(s.histogram[1]),
		float64(s.histogram[2]),
		float64(s.histogram[3]),
	}

	srcRows := [][]string{{"IP","pps"}}
	for _, kv := range s.topSrc {
		srcRows = append(srcRows, []string{kv.key, fmt.Sprintf("%d", kv.val)})
	}
	srcT.Rows = srcRows

	dstRows := [][]string{{"IP","pps"}}
	for _, kv := range s.topDst {
		dstRows = append(dstRows, []string{kv.key, fmt.Sprintf("%d", kv.val)})
	}
	dstT.Rows = dstRows
}



func capture(
	h *pcap.Handle,
	outPC string,
	rotateBytes int64,
	linkType layers.LinkType,
	out chan<- packetInfo,
) {
	var f *os.File
	var w *pcapgo.Writer

	open := func() {
		name := outPC
		if rotateBytes > 0 {
			ext := filepath.Ext(outPC)
			base := strings.TrimSuffix(outPC, ext)
			name = fmt.Sprintf("%s_%s%s", base, time.Now().Format("20060102_150405"), ext)
		}
		var err error
		f, err = os.Create(name)
		if err != nil {
			log.Fatalf("pcap open: %v", err)
		}
		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(2000, linkType)
	}

	if outPC != "" {
		open()
	}

	srcPackets := gopacket.NewPacketSource(h, h.LinkType())
	for pkt := range srcPackets.Packets() {
		if w != nil {
			_ = w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
			if rotateBytes > 0 {
				if info, _ := f.Stat(); info.Size() >= rotateBytes {
					f.Close()
					open()
				}
			}
		}
		proto, s, d := analyse(pkt)
		out <- packetInfo{len(pkt.Data()), proto, s, d}
	}
	if f != nil {
		f.Close()
	}
}



func aggregate(in <-chan packetInfo, out chan<- statsSnapshot) {
	var pps, bps, tcp, udp, icmp, oth uint64
	bins := [4]uint64{}
	srcMap := make(map[string]uint64)
	dstMap := make(map[string]uint64)
	tick := time.NewTicker(time.Second)

	for {
		select {
		case p := <-in:
			pps++; bps += uint64(p.size)
			switch p.proto {
			case "TCP": tcp++
			case "UDP": udp++
			case "ICMP": icmp++
			default: oth++
			}
			switch {
			case p.size <= 64:
				bins[0]++
			case p.size <= 512:
				bins[1]++
			case p.size <= 1500:
				bins[2]++
			default:
				bins[3]++
			}
			srcMap[p.src]++
			dstMap[p.dst]++

		case <-tick.C:
			out <- statsSnapshot{
				pps, bps, tcp, udp, icmp, oth,
				bins,
				topN(srcMap, 5),
				topN(dstMap, 5),
			}
			pps, bps, tcp, udp, icmp, oth = 0, 0, 0, 0, 0, 0
			bins = [4]uint64{}
			srcMap = make(map[string]uint64)
			dstMap = make(map[string]uint64)
		}
	}
}



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
	if len(arr) > n {
		return arr[:n]
	}
	return arr
}
