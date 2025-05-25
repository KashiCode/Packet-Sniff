package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
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

var (
	fList     = flag.Bool("list", false, "list interfaces and exit")
	fIdx      = flag.Int("n", 0, "capture by index from -list (1-based)")
	fIface    = flag.String("i", "", "capture by full device string (overrides -n)")
	fFilter   = flag.String("f", "", "BPF filter (icmp|tcp|udp shortcuts)")
	fPCAP     = flag.String("w", "", "write packets to <file.pcap>")
	fRotateMB = flag.Int("rotate-size", 0, "rotate PCAP every N MB (0=off)")
	fCSV      = flag.String("csv", "", "write per-second stats to <file.csv>")
	fLP       = flag.String("lp", "", "write stats in Influx line-protocol to <file.lp>")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `live_sniffer – live packet dashboard, PCAP dumper + stats exporter

Flags:
`)
		flag.PrintDefaults()
		fmt.Print(`

Hot-keys while TUI is running:
  p   pause / resume
  q   quit        (Ctrl-C also quits)
`)
	}
}

type packetInfo struct {
	size                    int
	proto, srcIP, srcPort   string
	dstIP, dstPort          string
}

type kv struct{ key string; val uint64 }

type FlowKey struct {
	Proto                string
	SrcIP, SrcPort       string
	DstIP, DstPort       string
}

type FlowStats struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Packets   uint64
	Bytes     uint64
}

type FlowDisplay struct {
	Key       string
	Packets   uint64
	Bytes     uint64
	Duration  float64
	Bps       float64
}

type snapshot struct {
	pps, bps, tcp, udp, icmp, oth uint64
	bin                           [4]uint64
	srcTop, dstTop                []kv
	flowTop                       []FlowDisplay
}

func analyse(pkt gopacket.Packet) (proto, srcIP, dstIP string) {
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
		srcIP, dstIP = h.SrcIP.String(), h.DstIP.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		h := ip6.(*layers.IPv6)
		srcIP, dstIP = h.SrcIP.String(), h.DstIP.String()
	} else {
		srcIP, dstIP = "<non-IP>", "<non-IP>"
	}
	return
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

func kvRows(arr []kv) [][]string {
	rows := make([][]string, len(arr))
	for i, kv := range arr {
		rows[i] = []string{kv.key, strconv.FormatUint(kv.val, 10)}
	}
	return rows
}

func flowRows(arr []FlowDisplay) [][]string {
	rows := make([][]string, len(arr))
	for i, f := range arr {
		rows[i] = []string{
			f.Key,
			strconv.FormatUint(f.Packets, 10),
			strconv.FormatUint(f.Bytes, 10),
			fmt.Sprintf("%.1f", f.Duration),
			fmt.Sprintf("%.0f", f.Bps),
		}
	}
	return rows
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

func scale(v, max uint64) int {
	if v >= max {
		return 100
	}
	return int(v * 100 / max)
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
			ts := time.Now().Format("20060102_150405")
			name = fmt.Sprintf("%s_%s%s", base, ts, ext)
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
	src := gopacket.NewPacketSource(h, h.LinkType())
	for pkt := range src.Packets() {
		if w != nil {
			_ = w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
			if rotateBytes > 0 {
				if info, _ := f.Stat(); info.Size() >= rotateBytes {
					f.Close()
					open()
				}
			}
		}
		proto, srcIP, dstIP := analyse(pkt)
		var srcPort, dstPort string
		if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
			t := tcp.(*layers.TCP)
			srcPort = t.SrcPort.String()
			dstPort = t.DstPort.String()
		} else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
			u := udp.(*layers.UDP)
			srcPort = u.SrcPort.String()
			dstPort = u.DstPort.String()
		}
		out <- packetInfo{
			size:    len(pkt.Data()),
			proto:   proto,
			srcIP:   srcIP,
			srcPort: srcPort,
			dstIP:   dstIP,
			dstPort: dstPort,
		}
	}
	if f != nil {
		f.Close()
	}
}

func aggregate(in <-chan packetInfo, out chan<- snapshot) {
	var pps, bps, tcp, udp, icmp, oth uint64
	bins := [4]uint64{}
	srcMap := make(map[string]uint64)
	dstMap := make(map[string]uint64)
	flowMap := make(map[FlowKey]*FlowStats)
	tick := time.NewTicker(time.Second)
	for {
		select {
		case p := <-in:
			now := time.Now()
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
			srcMap[p.srcIP]++
			dstMap[p.dstIP]++
			fk := FlowKey{Proto: p.proto, SrcIP: p.srcIP, SrcPort: p.srcPort, DstIP: p.dstIP, DstPort: p.dstPort}
			fs, ok := flowMap[fk]
			if !ok {
				fs = &FlowStats{FirstSeen: now}
				flowMap[fk] = fs
			}
			fs.LastSeen = now
			fs.Packets++
			fs.Bytes += uint64(p.size)
		case <-tick.C:
			flows := make([]FlowDisplay, 0, len(flowMap))
			for fk, fs := range flowMap {
				dur := fs.LastSeen.Sub(fs.FirstSeen).Seconds()
				bpsVal := float64(fs.Bytes) / dur
				key := fmt.Sprintf("%s %s:%s→%s:%s", fk.Proto, fk.SrcIP, fk.SrcPort, fk.DstIP, fk.DstPort)
				flows = append(flows, FlowDisplay{Key: key, Packets: fs.Packets, Bytes: fs.Bytes, Duration: dur, Bps: bpsVal})
			}
			sort.Slice(flows, func(i, j int) bool { return flows[i].Bytes > flows[j].Bytes })
			if len(flows) > 5 {
				flows = flows[:5]
			}
			out <- snapshot{
				pps, bps, tcp, udp, icmp, oth,
				bins,
				topN(srcMap, 5),
				topN(dstMap, 5),
				flows,
			}
			pps, bps, tcp, udp, icmp, oth = 0, 0, 0, 0, 0, 0
			bins = [4]uint64{}
			srcMap = make(map[string]uint64)
			dstMap = make(map[string]uint64)
			// keep flowMap for long-lived flows
		}
	}
}

func main() {
	flag.Parse()
	*fFilter = expandSimpleFilter(strings.Trim(*fFilter, "\"'"))
	if *fList {
		listIfaces()
		return
	}
	dev := resolveDevice(*fIface, *fIdx)
	handle, err := pcap.OpenLive(dev, 2000, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap open: %v", err)
	}
	defer handle.Close()
	if *fFilter != "" {
		if err := handle.SetBPFFilter(*fFilter); err != nil {
			log.Fatalf("bad filter: %v", err)
		}
	}
	rotateBytes := int64(*fRotateMB) * 1024 * 1024
	var csvW *csv.Writer
	if *fCSV != "" {
		f, err := os.Create(*fCSV)
		if err != nil {
			log.Fatalf("csv: %v", err)
		}
		defer f.Close()
		csvW = csv.NewWriter(f)
		csvW.Write([]string{"time", "pps", "bps", "tcp", "udp", "icmp", "other"})
		csvW.Flush()
	}
	var lpW *bufio.Writer
	if *fLP != "" {
		f, err := os.Create(*fLP)
		if err != nil {
			log.Fatalf("lp: %v", err)
		}
		defer f.Close()
		lpW = bufio.NewWriter(f)
	}
	pktCh := make(chan packetInfo, 4096)
	statCh := make(chan snapshot, 8)
	go capture(handle, *fPCAP, rotateBytes, handle.LinkType(), pktCh)
	go aggregate(pktCh, statCh)
	if err := ui.Init(); err != nil {
		log.Fatalf("termui: %v", err)
	}
	defer ui.Close()
	ppsG := widgets.NewGauge()
	bpsG := widgets.NewGauge()
	bar := widgets.NewBarChart()
	hist := widgets.NewBarChart()
	hist.BarColors = []ui.Color{
		ui.ColorRed,
		ui.ColorGreen,
		ui.ColorYellow,
		ui.ColorWhite,
	}
	hist.NumStyles = []ui.Style{
		ui.NewStyle(ui.ColorRed),
		ui.NewStyle(ui.ColorGreen),
		ui.NewStyle(ui.ColorYellow),
		ui.NewStyle(ui.ColorWhite),
	}
	srcT := widgets.NewTable()
	dstT := widgets.NewTable()
	flowT := widgets.NewTable()
	uiEvents := ui.PollEvents()
	heartbeat := time.NewTicker(500 * time.Millisecond)
	defer heartbeat.Stop()
	paused := false
	resize := func() {
		w, h := ui.TerminalDimensions()
		ppsG.SetRect(0, 0, w, 3)
		ppsG.Title = "Packets / sec"
		bpsG.SetRect(0, 3, w, 6)
		bpsG.Title = "Bytes / sec"
		bar.SetRect(0, 6, w, 12)
		bar.Title = "Protocol mix (pps)"
		bar.Labels = []string{"TCP", "UDP", "ICMP", "Other"}
		hist.SetRect(0, 12, w, 16)
		hist.Title = "Packet size histogram"
		hist.Labels = []string{"<=64B", "65–512B", "513–1500B", ">1500B"}
		srcW := w * 2 / 10
		dstW := w * 2 / 10
		srcT.SetRect(0, 16, srcW, h)
		srcT.Title = "Top source IPs (pps)"
		srcT.Rows = [][]string{{"IP", "pps"}}
		dstT.SetRect(srcW, 16, srcW+dstW, h)
		dstT.Title = "Top destination IPs (pps)"
		dstT.Rows = [][]string{{"IP", "pps"}}
		flowT.SetRect(srcW+dstW, 16, w, h)
		flowT.Title = "Top flows"
		flowT.Rows = [][]string{{"Flow", "pkts", "bytes", "dur(s)", "Bps"}}
	}
	resize()
	ui.Render(ppsG, bpsG, bar, hist, srcT, dstT, flowT)
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "<Resize>":
				ui.Clear()
				resize()
				ui.Render(ppsG, bpsG, bar, hist, srcT, dstT, flowT)
			case "p", "P":
				paused = !paused
			case "q", "Q", "<C-c>":
				return
			}
		case snap := <-statCh:
			if csvW != nil {
				csvW.Write([]string{
					time.Now().UTC().Format(time.RFC3339),
					strconv.FormatUint(snap.pps, 10),
					strconv.FormatUint(snap.bps, 10),
					strconv.FormatUint(snap.tcp, 10),
					strconv.FormatUint(snap.udp, 10),
					strconv.FormatUint(snap.icmp, 10),
					strconv.FormatUint(snap.oth, 10),
				})
				csvW.Flush()
			}
			if lpW != nil {
				lpW.WriteString(fmt.Sprintf(
					"live_sniffer pps=%d,bps=%d,tcp=%d,udp=%d,icmp=%d,other=%d %d\n",
					snap.pps, snap.bps, snap.tcp, snap.udp, snap.icmp, snap.oth,
					time.Now().UTC().UnixNano(),
				))
				lpW.Flush()
			}
			if paused {
				continue
			}
			ppsG.Percent = scale(snap.pps, 10000)
			ppsG.Label = fmt.Sprintf("%d pps", snap.pps)
			kb := snap.bps / 1024
			bpsG.Percent = scale(kb, 100000)
			bpsG.Label = fmt.Sprintf("%d KB/s", kb)
			bar.Data = []float64{
				float64(snap.tcp),
				float64(snap.udp),
				float64(snap.icmp),
				float64(snap.oth),
			}
			hist.Data = []float64{
				float64(snap.bin[0]),
				float64(snap.bin[1]),
				float64(snap.bin[2]),
				float64(snap.bin[3]),
			}
			srcT.Rows = append([][]string{{"IP", "pps"}}, kvRows(snap.srcTop)...)
			dstT.Rows = append([][]string{{"IP", "pps"}}, kvRows(snap.dstTop)...)
			flowT.Rows = append([][]string{{"Flow", "pkts", "bytes", "dur(s)", "Bps"}}, flowRows(snap.flowTop)...)
			ui.Render(ppsG, bpsG, bar, hist, srcT, dstT, flowT)
		case <-heartbeat.C:
			if !paused {
				ui.Render(ppsG, bpsG, bar, hist, srcT, dstT, flowT)
			}
		}
	}
}
