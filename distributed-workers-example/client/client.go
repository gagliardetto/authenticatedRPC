package main

import (
	dis "github.com/gagliardetto/authenticatedRPC"

	"crypto/tls"
	"fmt"
	"time"
)

var client dis.DistribClient

func init() {
	client = dis.NewClient()

	cert, err := tls.LoadX509KeyPair("keys-for-client/client.public.crt", "keys-for-client/client.private.key")
	if err != nil {
		fmt.Println(err)
		return
	}
	client.Config.Cert = cert

	client.Config.Server.VerifyCert = true
	client.Config.Server.Name = "distributed.server"
	client.Config.Server.CertPath = "keys-for-client/server.public.crt"
}

func main() {

	client.On(dis.ConnectEvent, func(cc dis.Context) {
		fmt.Println("Hey let's play ping-pong")

		localAddr := cc.Conn.LocalAddr()
		remoteAddr := cc.Conn.RemoteAddr()
		fmt.Println("Ping-pong match between: ", localAddr, " (me) and ", remoteAddr)

		requestPack := dis.Pack{
			Destination: "ping-pong",
			Payload:     "I'm going first",
		}

		fmt.Println("First strike")
		err := cc.Trigger(requestPack)
		if err != nil {
			fmt.Println(err)
		}
	})

	client.On("ping-pong", func(cc dis.Context) {

		fmt.Printf("\nNew ball from server: %q\n", cc.Data)
		time.Sleep(time.Millisecond * 1000)

		requestPack := dis.Pack{
			Destination: "ping-pong",
			Payload:     "Not this time",
		}
		err := cc.Trigger(requestPack)
		if err != nil {
			fmt.Println(err)
		}
	})

	client.On("myNameIs", func(cc dis.Context) (interface{}, error) {
		return "Tony Stark", nil
	})

	client.On("ciaoo", func(cc dis.Context) {

		fmt.Printf("new msg from server: %q\n", cc.Data)
		time.Sleep(time.Millisecond * 100)

		requestPack := dis.Pack{
			Destination: "ping",
			Payload:     "questo è connect",
		}

		responsePack, err := cc.Receive(requestPack)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("messaggio receive:", responsePack, err)
	})

	for {
		fmt.Println("Connecting to server...")
		if err := client.Connect("127.0.0.1:3333"); err != nil {
			fmt.Println("No connection to server or went down")
			time.Sleep(time.Second * 3)
			continue
		}
	}
}
