
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	//"os/signal"
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
	fList       = flag.Bool("list", false, "list interfaces and exit")
	fIdx        = flag.Int("n", 0, "capture by index from -list (1-based)")
	fIface      = flag.String("i", "", "capture by full device string (overrides -n)")
	fFilter     = flag.String("f", "", "BPF filter (icmp|tcp|udp shortcuts)")
	fPCAP       = flag.String("w", "", "write packets to <file.pcap>")
	fRotateMB   = flag.Int("rotate-size", 0, "rotate PCAP every N MB (0=off)")
	fCSV        = flag.String("csv", "", "write per-second stats to <file.csv>")
	fLP         = flag.String("lp", "", "write stats in Influx line-protocol to <file.lp>")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			`live_sniffer – live packet dashboard, PCAP dumper + stats exporter

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
	size       int
	proto, src string
	dst        string
}

type kv struct{ key string; val uint64 }

type snapshot struct {
	pps, bps            uint64
	tcp, udp, icmp, oth uint64
	bin                 [4]uint64
	srcTop, dstTop      []kv
}



func analyse(pkt gopacket.Packet) (proto, src, dst string) {
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
		h := ip4.(*layers.IPv4); src, dst = h.SrcIP.String(), h.DstIP.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		h := ip6.(*layers.IPv6); src, dst = h.SrcIP.String(), h.DstIP.String()
	} else {
		src, dst = "<non-IP>", "<non-IP>"
	}
	return
}

func scale(v, max uint64) int {
	if v >= max { return 100 }
	return int(v * 100 / max)
}



func main() {
	flag.Parse()
	*fFilter = expandSimpleFilter(strings.Trim(*fFilter, "\"'"))

	if *fList {
		listIfaces(); return
	}

	dev := resolveDevice(*fIface, *fIdx)
	handle, err := pcap.OpenLive(dev, 2000, true, pcap.BlockForever)
	if err != nil { log.Fatalf("pcap open: %v", err) }
	defer handle.Close()

	if *fFilter != "" {
		if err := handle.SetBPFFilter(*fFilter); err != nil {
			log.Fatalf("bad filter: %v", err)
		}
	}

	rotateBytes := int64(*fRotateMB) * 1024 * 1024

	
	var csvW *csv.Writer
	if *fCSV != "" {
		f, err := os.Create(*fCSV); if err != nil { log.Fatalf("csv: %v", err) }
		defer f.Close()
		csvW = csv.NewWriter(f)
		csvW.Write([]string{"time","pps","bps","tcp","udp","icmp","other"}); csvW.Flush()
	}

	
	var lpW *bufio.Writer
	if *fLP != "" {
		f, err := os.Create(*fLP); if err != nil { log.Fatalf("lp: %v", err) }
		defer f.Close()
		lpW = bufio.NewWriter(f)
	}

	
	pktCh  := make(chan packetInfo, 4096)
	statCh := make(chan snapshot, 8)
	go capture(handle, *fPCAP, rotateBytes, handle.LinkType(), pktCh)
	go aggregate(pktCh, statCh)

	
	if err := ui.Init(); err != nil { log.Fatalf("termui: %v", err) }
	defer ui.Close()

	
	ppsG := widgets.NewGauge(); bpsG := widgets.NewGauge()
	bar := widgets.NewBarChart(); hist := widgets.NewBarChart()
	srcT := widgets.NewTable();   dstT := widgets.NewTable()

	uiEvents := ui.PollEvents()
	heartbeat := time.NewTicker(500*time.Millisecond)
	defer heartbeat.Stop()
	paused := false

	resize := func() { w,h:=ui.TerminalDimensions()
		ppsG.SetRect(0,0,w,3); ppsG.Title="Packets / sec"
		bpsG.SetRect(0,3,w,6); bpsG.Title="Bytes / sec"

		bar.SetRect(0,6,w,12); bar.Title="Protocol mix"; bar.Labels=[]string{"TCP","UDP","ICMP","Other"}
		hist.SetRect(0,12,w,16); hist.Title="Size histogram"; hist.Labels=[]string{"<=64B","65–512","513–1500",">1500"}
		srcT.SetRect(0,16,w/2,h); srcT.Title="Top source"; srcT.Rows=[][]string{{"IP","pps"}}
		dstT.SetRect(w/2,16,w,h); dstT.Title="Top destination"; dstT.Rows=[][]string{{"IP","pps"}}
	}
	resize(); ui.Render(ppsG,bpsG,bar,hist,srcT,dstT)

	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "<Resize>": resize(); ui.Clear(); ui.Render(ppsG,bpsG,bar,hist,srcT,dstT)
			case "p","P":   paused = !paused
			case "q","Q","<C-c>": return
			}

		case snap := <-statCh:
			// exports
			if csvW!=nil {
				csvW.Write([]string{
					time.Now().UTC().Format(time.RFC3339),
					fmt.Sprint(snap.pps), fmt.Sprint(snap.bps),
					fmt.Sprint(snap.tcp), fmt.Sprint(snap.udp),
					fmt.Sprint(snap.icmp), fmt.Sprint(snap.oth)}); csvW.Flush()
			}
			if lpW!=nil {
				lpW.WriteString(fmt.Sprintf(
					"live_sniffer pps=%d,bps=%d,tcp=%d,udp=%d,icmp=%d,other=%d %d\n",
					snap.pps,snap.bps,snap.tcp,snap.udp,snap.icmp,snap.oth,
					time.Now().UTC().UnixNano())); lpW.Flush()
			}
			if paused { continue }

			ppsG.Percent=scale(snap.pps,10000); ppsG.Label=fmt.Sprintf("%d pps",snap.pps)
			kb:=snap.bps/1024; bpsG.Percent=scale(kb,100000); bpsG.Label=fmt.Sprintf("%d KB/s",kb)
			bar.Data=[]float64{float64(snap.tcp),float64(snap.udp),float64(snap.icmp),float64(snap.oth)}
			hist.Data=[]float64{float64(snap.bin[0]),float64(snap.bin[1]),float64(snap.bin[2]),float64(snap.bin[3])}

			srcT.Rows = append([][]string{{"IP","pps"}}, kvRows(snap.srcTop)...)
			dstT.Rows = append([][]string{{"IP","pps"}}, kvRows(snap.dstTop)...)
			ui.Render(ppsG,bpsG,bar,hist,srcT,dstT)

		case <-heartbeat.C:
			if !paused { ui.Render(ppsG,bpsG,bar,hist,srcT,dstT) }
		}
	}
}


func kvRows(arr []kv) [][]string {
	rows := make([][]string, len(arr))
	for i, kv := range arr { rows[i]=[]string{kv.key,strconv.FormatUint(kv.val,10)} }
	return rows
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




func aggregate(in <-chan packetInfo, out chan<- snapshot) {
	var pps, bps, tcp, udp, icmp, oth uint64
	bins := [4]uint64{}
	srcMap := make(map[string]uint64)
	dstMap := make(map[string]uint64)
	tick := time.NewTicker(time.Second)

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
			out <- snapshot{
				pps, bps, tcp, udp, icmp, oth,
				bins,
				topN(srcMap, 5),
				topN(dstMap, 5),
			}
			// reset counters
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
