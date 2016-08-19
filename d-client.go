package authenticatedRPC

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"time"
)

type (
	DistribClient struct {
		callbacks map[string]interface{}
		Conn      net.Conn
		Config    ClientConfig
		channels  FlowChannels
	}

	ClientConfig struct {
		DisableTLS bool
		Cert       tls.Certificate
		PrivateKey *rsa.PrivateKey
		Server     struct {
			EnableCertVerification bool
			ServerName             string
			ServerCertPath         string
			PublicKey              *rsa.PublicKey
			address                *net.TCPAddr
		}
	}
)

func NewClient() DistribClient {
	var newInstance DistribClient
	newInstance.callbacks = make(map[string]interface{})
	newInstance.channels = FlowChannels{}
	newInstance.channels.Channels = make(ChannelMap)

	return newInstance
}

func (client *DistribClient) Connect(indirizzo string) error {
	var conn net.Conn
	var err error

	address, err := net.ResolveTCPAddr("tcp", indirizzo)
	if err != nil {
		return err
	}
	client.Config.Server.address = address

	if !client.Config.DisableTLS {
		if len(client.Config.Cert.Certificate) < 1 {
			return fmt.Errorf("SSL is enabled, but no certificate was provided. Please provide a certificate (recommended) or disable SSL")
		}

		var serverCertPool *x509.CertPool

		if client.Config.Server.EnableCertVerification {

			serverCertPool = x509.NewCertPool()

			serverCert, err := ioutil.ReadFile(client.Config.Server.ServerCertPath)
			if err != nil {
				return fmt.Errorf("Can't open/find server certificate: %q", err)
			}

			if ok := serverCertPool.AppendCertsFromPEM([]byte(serverCert)); !ok {
				return fmt.Errorf("Failed to append server certificate to pool")
			}
		}

		clientTLSconfig := tls.Config{
			ServerName:         client.Config.Server.ServerName,
			Certificates:       []tls.Certificate{client.Config.Cert},
			InsecureSkipVerify: false,
			RootCAs:            serverCertPool,
		}
		clientTLSconfig.Rand = rand.Reader

		conn, err = tls.Dial("tcp", client.Config.Server.address.String(), &clientTLSconfig)
		if err != nil {
			return fmt.Errorf("Error connecting TLS:", err.Error())
		}
		debug("Connected via TLS to " + client.Config.Server.address.String())
	} else {
		conn, err = net.Dial("tcp", client.Config.Server.address.String())
		if err != nil {
			return fmt.Errorf("Error connectting plain text:", err.Error())
		}
		debug("Connected via plain text conn. to " + client.Config.Server.address.String())
	}

	client.Conn = conn

	// Is called when this client connects to a server·
	go func(client *DistribClient) {
		if _, ok := client.callbacks[ConnectEvent]; ok {
			debug("event triggered when connecting to the server!")
			err = client.Trigger(MetaPack{
				Pack: Pack{
					Destination: ConnectEvent,
					Payload:     "",
				},
				Type: triggerCallType,
			})
			if err != nil {
				fmt.Println(err)
			}
		}
	}(client)

	client.handleConnectionFromServer()

	return nil
}

func (client *DistribClient) handleConnectionFromServer() {
	conn := client.Conn

	defer func(conn net.Conn) {
		conn.Close()
		localAddr := conn.LocalAddr()
		remoteAddr := conn.RemoteAddr()
		fmt.Println(localAddr, remoteAddr)
		client.Conn = nil
	}(conn)

	for {
		reader := bufio.NewReader(conn)
		buf, isPrefix, err := reader.ReadLine()

		if err != nil {
			debug("Error reading (client):\"", err.Error(), "\"")
			conn.Close()
			break
		}

		if !isPrefix && len(buf) > 0 {
			go client.handleMessageFromServer(buf)
		}
	}
}

func (client *DistribClient) handleMessageFromServer(buf []byte) {
	debug("received len:", len(buf))
	debugf("%v#\n", string(buf))

	metaPack, err := decodeMetaPack(buf)
	if err != nil {
		debug("CLIENT", err)
		return
	}

	encodedPack, err := metaPack.Pack.encode()
	if err != nil {
		fmt.Println(err)
		return
	}
	encodedMessagePackHash := hash(encodedPack)

	hashesMatch := bytes.Equal(encodedMessagePackHash, metaPack.Hash)
	if !hashesMatch {
		fmt.Println("Hash equation failed:", string(encodedMessagePackHash), hash(metaPack.Hash))
		return
	}

	/*
		packIsNotExpired := time.Now().Sub(metaPack.Pack.IssueDate) > client.Config.PackExpiration
		if packIsNotExpired {
			fmt.Println("metaPack.Pack expired:", time.Now().Sub(metaPack.Pack.IssueDate), ">", client.Config.PackExpiration)
			return
		}
	*/

	packIsTriggerCallType := metaPack.CallID != "" && metaPack.Type == triggerCallType
	packIsTriggerAnswerType := metaPack.CallID != "" && metaPack.Type == triggerAnswerType
	packIsRequestCallType := metaPack.CallID != "" && metaPack.Type == requestCallType
	packIsRequestAnswerType := metaPack.CallID != "" && metaPack.Type == requestAnswerType

	if packIsTriggerCallType {
		fmt.Println("Type:", triggerCallType)
		err = client.Trigger(metaPack)
		if err != nil {
			fmt.Println(err)
			return
		}
		return
	} else if packIsTriggerAnswerType {
		fmt.Println("Type:", triggerAnswerType)

	} else if packIsRequestCallType {
		fmt.Println("Type:", requestCallType)
		// send back error if: anything goes wrong up to this point, and `data, err`:= ...
		data, err := client.Request(metaPack) // DOES wait for client.callbacks[destination] to finish executing

		cc, err := client.newContext(metaPack.Pack)
		if err != nil {
			fmt.Println(err)
			return
		}

		responseMetaPack := &MetaPack{
			Pack: Pack{
				Payload: data,
				Error:   err,
			},
			CallID: metaPack.CallID,
			Type:   requestAnswerType,
		}
		cc.compileAndSendMetaPack(responseMetaPack)
		return
	} else if packIsRequestAnswerType {
		fmt.Println("Type:", requestAnswerType)
		client.channels.RLock()
		defer func() { recover() }()
		if _, ok := client.channels.Channels[metaPack.CallID]; ok {
			client.channels.Channels[metaPack.CallID].Channel <- metaPack.Pack
		}
		client.channels.RUnlock()
		return
	}
	fmt.Println("Unsupported Type:", metaPack.Type)
	return
}

func (client *DistribClient) newContext(pack Pack) (Context, error) {
	var cc Context = Context{
		Data: pack,
		Conn: client.Conn,
		Local: Local{
			PrivateKey: client.Config.PrivateKey,
			channels:   &client.channels,
		},
		Remote: Remote{
			PublicKey: client.Config.Server.PublicKey,
		},
	}
	return cc, nil
}

func (client *DistribClient) Trigger(metaPack MetaPack) error {

	if _, ok := client.callbacks[string(metaPack.Pack.Destination)]; !ok {
		return fmt.Errorf("Callback %q does not exist", string(metaPack.Pack.Destination))
	}

	cc, err := client.newContext(metaPack.Pack)
	if err != nil {
		fmt.Println(err)
		return err
	}

	switch client.callbacks[string(metaPack.Pack.Destination)].(type) {
	case func(Context):
		{
			fmt.Println("in Trigger, type is func(Context)")
			go client.callbacks[string(metaPack.Pack.Destination)].(func(Context))(cc)
			return nil
		}
	default:
		{
			return fmt.Errorf("Callback %q is not of right format (%#v instead of func(Context))", string(metaPack.Pack.Destination), client.callbacks[string(metaPack.Pack.Destination)])
		}
	}
}

func (client *DistribClient) Request(metaPack MetaPack) (string, error) {

	if _, ok := client.callbacks[string(metaPack.Pack.Destination)]; !ok {
		return "", fmt.Errorf("Callback %q does not exist", string(metaPack.Pack.Destination))
	}

	cc, err := client.newContext(metaPack.Pack)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	switch client.callbacks[string(metaPack.Pack.Destination)].(type) {
	case func(Context) (string, error):
		{
			fmt.Println("in Trigger, type is func(Context) (string, error)")
			data, err := client.callbacks[string(metaPack.Pack.Destination)].(func(Context) (string, error))(cc)
			fmt.Println("in Trigger, data, err:=", data, err)
			return data, err
		}
	}
	return "", fmt.Errorf("Callback %q is not of right format (%#v instead of func(Context) (string, error))", string(metaPack.Pack.Destination), client.callbacks[string(metaPack.Pack.Destination)])
}

func (client *DistribClient) On(funcName string, callback interface{}) error {
	if _, ok := client.callbacks[funcName]; ok {
		panic(fmt.Sprintf("Callback name %q already existing; please choose a different one", funcName))
	}

	client.callbacks[funcName] = callback
	return nil
}
