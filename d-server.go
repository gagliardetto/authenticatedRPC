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

	"github.com/renstrom/shortuuid"
)

type (
	DistribServer struct {
		callbacks map[string]interface{}
		clients   map[string]Client
		Config    ServerConfig
		channels  FlowChannels
	}

	ServerConfig struct {
		DisableTLS bool
		Cert       tls.Certificate
		PrivateKey *rsa.PrivateKey
		Client     struct {
			EnableCertVerification bool
			ServerName             string
			ServerCertPath         string
			PublicKey              *rsa.PublicKey
		}
		address *net.TCPAddr
	}

	Client struct {
		Conn      net.Conn
		PublicKey *rsa.PublicKey
	}
)

func NewServer() DistribServer {
	var newInstance DistribServer
	newInstance.callbacks = make(map[string]interface{})
	newInstance.clients = make(map[string]Client)
	newInstance.channels = FlowChannels{}
	newInstance.channels.Channels = make(ChannelMap)

	return newInstance
}

func (server *DistribServer) CountClients() int {
	return len(server.clients)
}

func (server *DistribServer) Run(indirizzo string) error {
	var listen net.Listener
	var err error

	address, err := net.ResolveTCPAddr("tcp", indirizzo)
	if err != nil {
		return err
	}
	server.Config.address = address

	if !server.Config.DisableTLS {
		if len(server.Config.Cert.Certificate) < 1 {
			return fmt.Errorf("Error: SSL is enabled, but no certificate was provided. Please provide certificate (recommended) or disable SSL.")
		}

		var clientCertPool *x509.CertPool

		if server.Config.Client.EnableCertVerification {

			clientCertPool = x509.NewCertPool()

			serverCert, err := ioutil.ReadFile(server.Config.Client.ServerCertPath)
			if err != nil {
				return fmt.Errorf("Can't open/find client certificate: %q", err)
			}

			if ok := clientCertPool.AppendCertsFromPEM([]byte(serverCert)); !ok {
				return fmt.Errorf("Failed to append client certificate to pool")
			}
		}

		serverTLSconfig := tls.Config{
			Certificates: []tls.Certificate{server.Config.Cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCertPool,
		}
		serverTLSconfig.Rand = rand.Reader

		listen, err = tls.Listen("tcp", server.Config.address.String(), &serverTLSconfig)
		if err != nil {
			return fmt.Errorf("Error listening TLS:", err.Error())
		}
		debug("Listening (TLS) on " + server.Config.address.String())
	} else {
		listen, err = net.Listen("tcp", server.Config.address.String())
		if err != nil {
			return fmt.Errorf("Error listening plain text:", err.Error())
		}
		debug("Listening (plain) on " + server.Config.address.String())
	}

	// Close the listener when the application closes.
	defer listen.Close()

	for {
		// Listen for an incoming connection.
		conn, err := listen.Accept()
		if err != nil {
			debug("Error accepting: ", err.Error())
			continue
		}

		uuu := shortuuid.New()
		fmt.Println(uuu)
		client := Client{
			Conn:      conn,
			PublicKey: server.Config.Client.PublicKey,
		}
		server.clients[uuu] = client

		// Is called when a client connects to this server.
		go func(server *DistribServer) {
			if _, ok := server.callbacks[ConnectEvent]; ok {
				debug("event triggered when a client connects to this server!")
				err = server.Trigger(uuu, MetaPack{
					Pack: Pack{
						Destination: ConnectEvent,
						Payload:     "",
					},
					Type: triggerCallType,
				})
				if err != nil {
					debug(err)
				}
			}
		}(server)

		// Handle connections in a new goroutine.
		go server.handleConnectionFromClient(uuu, conn)
	}
}

func (server *DistribServer) handleConnectionFromClient(uuu string, conn net.Conn) {

	defer func(conn net.Conn) {
		defer delete(server.clients, uuu)
		conn.Close()
		localAddr := conn.LocalAddr()
		remoteAddr := conn.RemoteAddr()
		fmt.Println(localAddr, remoteAddr)
	}(conn)

	for {
		reader := bufio.NewReader(conn)
		buf, isPrefix, err := reader.ReadLine()

		if err != nil {
			fmt.Println("Error reading (server):\"", err.Error(), "\"")
			conn.Close()
			break
		}

		if !isPrefix && len(buf) > 0 {
			go server.handleServerMessage(uuu, buf)
		}
	}
}

func (server *DistribServer) handleServerMessage(uuu string, buf []byte) {
	debug("received len:", len(buf))
	debugf("%v#\n", string(buf))

	metaPack, err := decodeMetaPack(buf)
	if err != nil {
		debug("SERVER", err)
		return
	}

	encodedPack, err := metaPack.Pack.encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	/*encodedMessagePackHash := hash(encodedPack)
	hashesMatch := bytes.Equal(encodedMessagePackHash, metaPack.Hash)
	if !hashesMatch {
		fmt.Println("Hash equation failed:", string(encodedMessagePackHash), hash(metaPack.Hash))
		return
	}
	*/

	/*
		packIsNotExpired := time.Now().Sub(metaPack.Pack.IssueDate) > server.Config.PackExpiration
		if packIsNotExpired {
			fmt.Println("metaPack.Pack expired:", time.Now().Sub(metaPack.Pack.IssueDate), ">", server.Config.PackExpiration)
			return
		}
	*/

	packIsTriggerCallType := metaPack.CallID != "" && metaPack.Type == triggerCallType
	packIsTriggerAnswerType := metaPack.CallID != "" && metaPack.Type == triggerAnswerType
	packIsRequestCallType := metaPack.CallID != "" && metaPack.Type == requestCallType
	packIsRequestAnswerType := metaPack.CallID != "" && metaPack.Type == requestAnswerType

	if packIsTriggerCallType {
		debug("Type:", triggerCallType)
		// send back error if: anything goes wrong up to this point (up to callback does not exist)
		err = server.Trigger(uuu, metaPack) // does NOT wait for server.callbacks[something] to finish executing
		if err != nil {
			fmt.Println(err)
			return
		}
		return
	} else if packIsTriggerAnswerType {
		debug("Type:", triggerAnswerType)

	} else if packIsRequestCallType {
		debug("Type:", requestCallType)
		// send back error if: anything goes wrong up to this point, and `data, err`:= ...
		data, err := server.Request(uuu, metaPack) // DOES wait for server.callbacks[destination] to finish executing

		cc, err := server.newContext(uuu, metaPack.Pack)
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
		debug("Type:", requestAnswerType)
		server.channels.RLock()
		if _, ok := server.channels.Channels[metaPack.CallID]; ok {
			server.channels.Channels[metaPack.CallID].Channel <- metaPack.Pack
		}
		server.channels.RUnlock()
		return
	}
	fmt.Println("Unsupported Type:", metaPack.Type)
	return
}

func (server *DistribServer) newContext(uuu string, pack Pack) (Context, error) {
	var cc Context = Context{
		Data: pack,
		Conn: server.clients[uuu].Conn,
		Local: Local{
			PrivateKey: server.Config.PrivateKey,
			channels:   &server.channels,
		},
		Remote: Remote{
			PublicKey: server.clients[uuu].PublicKey,
		},
	}
	return cc, nil
}

func (server *DistribServer) Trigger(uuu string, metaPack MetaPack) error {

	if _, ok := server.callbacks[string(metaPack.Pack.Destination)]; !ok {
		return fmt.Errorf("Callback %q does not exist", string(metaPack.Pack.Destination))
	}

	cc, err := server.newContext(uuu, metaPack.Pack)
	if err != nil {
		fmt.Println(err)
		return err
	}

	switch server.callbacks[string(metaPack.Pack.Destination)].(type) {
	case func(Context):
		{
			fmt.Println("in Trigger, type is func(Context)")
			go server.callbacks[string(metaPack.Pack.Destination)].(func(Context))(cc)
			return nil
		}
	default:
		{
			return fmt.Errorf("Callback %q is not of right format (%#v instead of func(Context))", string(metaPack.Pack.Destination), server.callbacks[string(metaPack.Pack.Destination)])
		}
	}
}

func (server *DistribServer) Request(uuu string, metaPack MetaPack) (string, error) {

	if _, ok := server.callbacks[string(metaPack.Pack.Destination)]; !ok {
		return "", fmt.Errorf("Callback %q does not exist", string(metaPack.Pack.Destination))
	}

	cc, err := server.newContext(uuu, metaPack.Pack)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	switch server.callbacks[string(metaPack.Pack.Destination)].(type) {
	case func(Context) (string, error):
		{
			fmt.Println("in Trigger, type is func(Context) (string, error)")
			data, err := server.callbacks[string(metaPack.Pack.Destination)].(func(Context) (string, error))(cc)
			fmt.Println("in Trigger, data, err:=", data, err)
			return data, err
		}
	}
	return "", fmt.Errorf("Callback %q is not of right format (%#v instead of func(Context) (string, error))", string(metaPack.Pack.Destination), server.callbacks[string(metaPack.Pack.Destination)])
}

func (server *DistribServer) On(funcName string, callback interface{}) error {
	if _, ok := server.callbacks[funcName]; ok {
		panic(fmt.Sprintf("Callback name %q already existing; please choose a different one", funcName))
	}

	server.callbacks[funcName] = callback
	return nil
}
