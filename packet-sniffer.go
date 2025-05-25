
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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
	size      int
	proto     string
	src, dest string
}

type kv struct{ key string; val uint64 }

type statsSnapshot struct {
	pps, bps            uint64
	tcp, udp, icmp, oth uint64
	topSrc, topDst      []kv
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
		h := ip4.(*layers.IPv4)
		src, dst = h.SrcIP.String(), h.DstIP.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		h := ip6.(*layers.IPv6)
		src, dst = h.SrcIP.String(), h.DstIP.String()
	} else {
		src, dst = "<non-IP>", "<non-IP>"
	}
	return
}



func main() {

	list  := flag.Bool("list", false, "list interfaces and exit")
	idx   := flag.Int("n", 0, "index from -list (1-based)")
	iface := flag.String("i", "", "exact device string (overrides -n)")
	filter := flag.String("f", "", "BPF filter, e.g. 'tcp port 443'")
	outPC := flag.String("w", "", "write raw packets to <file.pcap>")
	outCSV := flag.String("csv", "", "write per-second stats to <file.csv>")
	outLP := flag.String("lp", "", "write per-second stats in Influx line-protocol to <file.lp>")
	flag.Parse()
	*filter = expandSimpleFilter(strings.Trim(*filter, "\"'"))

	
	if *list {
		listIfaces()
		return
	}


	dev := resolveDevice(*iface, *idx)


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

	var dumper *pcapgo.Writer
	var dumpFile *os.File
	if *outPC != "" {
		f, err := os.Create(*outPC)
		if err != nil {
			log.Fatalf("pcap writer: %v", err)
		}
		dumpFile = f
		dumper = pcapgo.NewWriter(f)
		dumper.WriteFileHeader(2000, handle.LinkType())
		fmt.Printf("[+] Writing packets to %s …\n", *outPC)
	}


	var csvWriter *csv.Writer
	var csvFile *os.File
	if *outCSV != "" {
		f, err := os.Create(*outCSV)
		if err != nil {
			log.Fatalf("csv writer: %v", err)
		}
		csvFile = f
		csvWriter = csv.NewWriter(f)
		csvWriter.Write([]string{"time","pps","bps","tcp","udp","icmp","other"})
		csvWriter.Flush()
		fmt.Printf("[+] Writing stats to %s …\n", *outCSV)
	}

	
	var lpFile *os.File
	var lpWriter *bufio.Writer
	if *outLP != "" {
		f, err := os.Create(*outLP)
		if err != nil {
			log.Fatalf("line-protocol writer: %v", err)
		}
		lpFile = f
		lpWriter = bufio.NewWriter(f)
		fmt.Printf("[+] Writing LP to %s …\n", *outLP)
	}

	fmt.Printf("[*] Capturing on %s  –  q quit | p pause | t toggle view …\n", dev)


	pktCh := make(chan packetInfo, 4096)
	statCh := make(chan statsSnapshot, 8)
	go capture(handle, dumper, pktCh)
	go aggregate(pktCh, statCh)


	if err := ui.Init(); err != nil {
		log.Fatalf("termui init: %v", err)
	}
	defer ui.Close()


	gPPS := widgets.NewGauge(); gPPS.Title="Packets / sec"; gPPS.SetRect(0,0,60,3)
	gBPS := widgets.NewGauge(); gBPS.Title="Bytes / sec";   gBPS.SetRect(0,3,60,6)

	bar := widgets.NewBarChart()
	bar.Title="Protocol mix (pps)"
	bar.Labels=[]string{"TCP","UDP","ICMP","Other"}
	bar.SetRect(0,6,60,14)

	table := widgets.NewTable()
	table.Rows = [][]string{{"IP","pps"}}
	table.SetRect(0,14,60,23)

	help := widgets.NewParagraph()
	help.Text="[t] toggle view   |   [p] pause/resume   |   [q] quit"
	help.Border=false
	help.TextStyle=ui.NewStyle(ui.ColorYellow)
	help.SetRect(0,23,60,25)

	ui.Render(gPPS, gBPS, bar, table, help)


	uiCh := make(chan ui.Event,20)
	go func(){ for e := range ui.PollEvents() { uiCh<-e } }()
	heartbeat := time.NewTicker(500*time.Millisecond)
	defer heartbeat.Stop()

	paused := false
	viewMode := 0 
	sigsCh := make(chan os.Signal,1)
	signal.Notify(sigsCh, os.Interrupt)

	for {
		select {
		case <-sigsCh:
			if dumpFile!=nil { dumpFile.Close() }
			if csvFile!=nil  { csvFile.Close() }
			if lpFile!=nil   { lpFile.Close() }
			return

		case e := <-uiCh:
			switch e.ID {
			case "q","Q","<C-c>":
				if dumpFile!=nil { dumpFile.Close() }
				if csvFile!=nil  { csvFile.Close() }
				if lpFile!=nil   { lpFile.Close() }
				return
			case "p","P":
				paused = !paused
			case "t","T":
				viewMode = (viewMode+1)%3
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
						snap.pps, snap.bps, snap.tcp, snap.udp, snap.icmp, snap.oth, ts))
				lpWriter.Flush()
			}

			if paused {
				continue
			}
			updateUI(gPPS, gBPS, bar, table, help, snap, viewMode)
			ui.Render(gPPS, gBPS, bar, table, help)

		case <-heartbeat.C:
			if !paused {
				ui.Render(gPPS, gBPS, bar, table, help)
			}
		}
	}
}



func updateUI(
	gPPS, gBPS *widgets.Gauge,
	bar *widgets.BarChart,
	table *widgets.Table,
	help *widgets.Paragraph,
	s statsSnapshot,
	mode int,
) {
	gPPS.Label, gPPS.Percent = fmt.Sprintf("%d pps", s.pps), int(scale(s.pps,10000))
	kb := s.bps/1024
	gBPS.Label, gBPS.Percent = fmt.Sprintf("%d KB/s", kb), int(scale(kb,100000))
	bar.Data = []float64{float64(s.tcp),float64(s.udp),float64(s.icmp),float64(s.oth)}

	switch mode {
	case 0:
		table.Title="[S]ource IPs (pps)"
		table.Rows = toRows(s.topSrc)
	case 1:
		table.Title="[D]estination IPs (pps)"
		table.Rows = toRows(s.topDst)
	case 2:
		table.Title="[B] Src+Dst (pps)"
		table.Rows = toRows(mergeKV(s.topSrc,s.topDst))
	}
}

func toRows(arr []kv) [][]string {
	rows := [][]string{{"IP","pps"}}
	for _, kv := range arr {
		rows = append(rows, []string{kv.key,fmt.Sprintf("%d",kv.val)})
	}
	return rows
}



func capture(h *pcap.Handle, dump *pcapgo.Writer, out chan<- packetInfo) {
	src := gopacket.NewPacketSource(h,h.LinkType())
	for pkt := range src.Packets() {
		if dump!=nil {
			_ = dump.WritePacket(pkt.Metadata().CaptureInfo,pkt.Data())
		}
		proto, s, d := analyse(pkt)
		out <- packetInfo{len(pkt.Data()), proto, s, d}
	}
}

func aggregate(in <-chan packetInfo, out chan<- statsSnapshot) {
	var pps,bps,tcp,udp,icmp,oth uint64
	srcMap := map[string]uint64{}
	dstMap := map[string]uint64{}
	tick := time.NewTicker(time.Second)

	for {
		select {
		case p := <-in:
			pps++; bps+=uint64(p.size)
			switch p.proto {
			case "TCP": tcp++
			case "UDP": udp++
			case "ICMP": icmp++
			default: oth++
			}
			srcMap[p.src]++
			dstMap[p.dest]++

		case <-tick.C:
			out <- statsSnapshot{
				pps,bps,tcp,udp,icmp,oth,
				topN(srcMap,5), topN(dstMap,5),
			}
			pps,bps,tcp,udp,icmp,oth=0,0,0,0,0,0
			srcMap,dstMap = map[string]uint64{}, map[string]uint64{}
		}
	}
}

/* ───────── utilities ───────── */

func listIfaces() {
	devs,_ := pcap.FindAllDevs()
	fmt.Println("Capture interfaces:")
	for i,d := range devs {
		desc := d.Description; if desc=="" { desc=d.Name }
		fmt.Printf("%2d. %-45s (%s)\n", i+1, d.Name, desc)
	}
}

func resolveDevice(custom string, idx int) string {
	if custom!="" { return custom }
	devs,_ := pcap.FindAllDevs()
	if idx>0 && idx<=len(devs) { return devs[idx-1].Name }
	for _,d := range devs {
		low := strings.ToLower(d.Name+d.Description)
		if strings.Contains(low,"loopback")||strings.HasPrefix(low,"lo") { continue }
		return d.Name
	}
	return devs[0].Name
}

func scale(v,max uint64) uint64 {
	if v>=max { return 100 }
	return v*100/max
}

func expandSimpleFilter(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "icmp": return "icmp"
	case "tcp":  return "tcp"
	case "udp":  return "udp"
	default:     return s
	}
}

func topN(m map[string]uint64,n int) []kv {
	arr := make([]kv,0,len(m))
	for k,v := range m {
		arr = append(arr, kv{k,v})
	}
	sort.Slice(arr, func(i,j int)bool { return arr[i].val>arr[j].val })
	if len(arr)>n { arr = arr[:n] }
	return arr
}

func mergeKV(a,b []kv) []kv {
	combined := make(map[string]uint64)
	for _,kv := range a { combined[kv.key]+=kv.val }
	for _,kv := range b { combined[kv.key]+=kv.val }
	return topN(combined,5)
}
