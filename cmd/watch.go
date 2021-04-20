package cmd

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/ghedo/go.pkt/capture/pcap"
	"github.com/ghedo/go.pkt/filter"
	"github.com/ghedo/go.pkt/layers"
	"github.com/spf13/cobra"
)

func NewWatchCmd() *cobra.Command {
	watchCmd := &cobra.Command{
		Use:   "watch <interface>",
		Short: "Prints the network packets to stdout",
		Long: `It can show all network packets in default output stream
			   and filter them by port and socket protocol (TCP/UDP)`,
		Args: cobra.MinimumNArgs(1),
		Run:  watch,
	}
	watchCmd.Flags().Int("port", 0, "Network port. Usage --port=80")
	watchCmd.Flags().Bool("tcp", false, "Only TCP packets. Usage --tcp")
	watchCmd.Flags().Bool("udp", false, "Only UDP packets. Usage --udp")

	return watchCmd
}

func watch(cmd *cobra.Command, args []string) {
	iface := args[0]
	port, err := strconv.Atoi(cmd.Flag("port").Value.String())
	if err != nil {
		log.Fatalf("error on parsing port flag: %s", err)
	}
	tcpOnly, err := strconv.ParseBool(cmd.Flag("tcp").Value.String())
	if err != nil {
		log.Fatalf("error on parsing tcp flag: %s", err)
	}
	udpOnly, err := strconv.ParseBool(cmd.Flag("udp").Value.String())
	if err != nil {
		log.Fatalf("error on parsing udp flag: %s", err)
	}
	log.Printf("interface: %s", iface)
	log.Printf("port: %d", port)
	log.Printf("only tcp: %v", tcpOnly)
	log.Printf("only udp: %v", udpOnly)

	src, err := pcap.Open(iface)
	if err != nil {
		log.Fatalf("error opening iface: %s", err)
	}
	defer src.Close()

	err = src.Activate()
	if err != nil {
		log.Fatalf("error activating source: %s", err)
	}

	terms := []string{}
	if tcpOnly {
		terms = append(terms, "tcp")
	} else if udpOnly {
		terms = append(terms, "udp")
	}
	if port > 0 {
		terms = append(terms, fmt.Sprintf("port %d", port))
	}

	if len(terms) > 0 {
		flt, err := filter.Compile(strings.Join(terms, " "), src.LinkType(), false)
		if err != nil {
			log.Fatalf("error parsing filter: %s", err)
		}
		defer flt.Cleanup()

		err = src.ApplyFilter(flt)
		if err != nil {
			log.Fatalf("error applying filter: %s", err)
		}
	}

	for {
		buf, err := src.Capture()
		if err != nil {
			log.Fatalf("error on capturing packet: %s", err)
		}

		if buf == nil {
			break
		}

		receivedPacket, err := layers.UnpackAll(buf, src.LinkType())
		if err != nil {
			log.Fatalf("error on unpacking packet: %s", err)
		}

		log.Println(receivedPacket)
	}
}
