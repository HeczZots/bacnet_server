package main

import (
	"bacnet_ecosystem_test/btypes"
	dec "bacnet_ecosystem_test/decoder"
	"bacnet_ecosystem_test/wireshark"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"github.com/urfave/cli"
)

const DebugLevel = 0

var myIp = "192.168.5.114"
var bac0 = 47808

// 1 broadcast mode
// 2 unicast mode
// 0 multicast mode
var mod = 2
var ObjList string

func main() {
	app := cli.NewApp()
	app.Name = "Bacnet simple server"
	app.Usage = "Server for transferring data with Bacnet client"
	app.Version = "1"
	app.Commands = []cli.Command{
		{
			Name: "start",
			Aliases: []string{
				"s",
			},
			Usage:  "Start server",
			Action: start_server,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "hex",
					Usage:       "convert hex string to byte array",
					Destination: &ObjList,
				},
			},
		},
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := app.Run(os.Args)
		if err != nil {
			log.Println(err)
		}
		os.Exit(3)
	}()
}

func start_server(c *cli.Context) {
	ol := wireshark.NewObjList(ObjList)
	fmt.Println(ol)
	_, ipNet, err := net.ParseCIDR(btypes.FindCIDR(myIp))
	if err != nil {
		log.Printf(err.Error())
		return
	}
	mw := io.MultiWriter(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "2006.01.02 15:04:05.000",
	})
	l := zerolog.New(mw).With().Timestamp().Logger()
	l = l.Level(zerolog.Level(DebugLevel))
	broadcast := net.IP(make([]byte, 4))
	for i := range broadcast {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}

	// myAddr := IPPortToAddress(ip, bac0)
	broadcastAddr := btypes.IPPortToAddress(broadcast, bac0)
	listenAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", myIp, bac0))

	list, err := net.ListenUDP("udp", listenAddr)

	if err != nil {
		l.Fatal().Err(err)
		return
	}

	l.Info().Msgf("listening on started %s", listenAddr)
	for {
		dest, err := broadcastAddr.UDPAddr()
		if err != nil {
			l.Err(err)
			return
		}
		b := make([]byte, 1476)
		n, source, err := list.ReadFromUDP(b)
		if err != nil {
			l.Err(err)
			continue
		}

		go func(b []byte) {
			decoder := dec.NewDecoder(b)

			if !decoder.IsWhoIs(b[:n]) || !decoder.IsScan(b[:n]) {
				return
			}

			l.Info().Msgf("received Who is")
			for _, iam := range IAmArr {
				_, err = list.WriteToUDP(iam, &dest)
			}

			l.Info().Msgf("Iam To %v ", source)

			if err != nil {
				l.Err(err)
				return
			}
		}(b)
	}
}
