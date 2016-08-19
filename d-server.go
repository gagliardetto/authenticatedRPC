package authenticatedRPC

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"sync"

	"github.com/renstrom/shortuuid"
)

type (
	DistribServer struct {
		callbacks map[string]interface{}
		clients   Clients
		channels  FlowChannels

		sync.Mutex
		dispatcher   *Dispatcher
		jobQueue     chan Job
		maxWorkers   int
		maxQueueSize int

		Config ServerConfig
	}

	Clients map[string]Client

	ServerConfig struct {
		DisableTLS bool
		Cert       tls.Certificate
		PrivateKey *rsa.PrivateKey
		Client     struct {
			VerifyCert bool
			Name       string
			CertPath   string
			PublicKey  *rsa.PublicKey
		}
		address *net.TCPAddr
	}

	Client struct {
		Conn      net.Conn
		PublicKey *rsa.PublicKey
		Id        string
	}
)

func NewServer() DistribServer {
	var newServer DistribServer
	newServer.callbacks = make(map[string]interface{})
	newServer.clients = make(map[string]Client)
	newServer.channels = FlowChannels{}
	newServer.channels.Channels = make(ChannelMap)

	newServer.maxWorkers = 5
	newServer.maxQueueSize = 100

	return newServer
}

func (server *DistribServer) Run(rawAddress string) error {
	var listener net.Listener
	var err error

	server.Config.address, err = net.ResolveTCPAddr("tcp", rawAddress)
	if err != nil {
		return err
	}

	// Create the job queue.
	server.jobQueue = make(chan Job, server.maxQueueSize)

	// Start the dispatcher.
	server.dispatcher = NewDispatcher(server.jobQueue, server.maxWorkers)
	server.runDispatcher()

	if server.Config.DisableTLS {

		listener, err = net.Listen("tcp", server.Config.address.String())
		if err != nil {
			return fmt.Errorf("Error listening plain text:", err.Error())
		}
		debug("Listening (plain) on " + server.Config.address.String())

	} else {

		if len(server.Config.Cert.Certificate) < 1 {
			panic("Error: SSL is enabled, but no certificate was provided. Please provide certificate (recommended) or disable SSL.")
		}

		var clientCertPool *x509.CertPool

		if server.Config.Client.VerifyCert {

			clientCertPool = x509.NewCertPool()

			serverCert, err := ioutil.ReadFile(server.Config.Client.CertPath)
			if err != nil {
				panic(fmt.Sprintf("Can't open/find client certificate: %q", err))
			}

			if ok := clientCertPool.AppendCertsFromPEM([]byte(serverCert)); !ok {
				panic("Failed to append client certificate to pool")
			}
		}

		serverTLSconfig := tls.Config{
			Certificates: []tls.Certificate{server.Config.Cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCertPool,

			InsecureSkipVerify: false,
		}
		serverTLSconfig.Rand = rand.Reader

		listener, err = tls.Listen("tcp", server.Config.address.String(), &serverTLSconfig)
		if err != nil {
			return fmt.Errorf("Error listening TLS: %v", err.Error())
		}
		debug("Listening (TLS) on " + server.Config.address.String())
	}

	// Close the listener when the application closes.
	defer listener.Close()

	for {
		// Listen for an incoming connection.
		conn, err := listener.Accept()
		if err != nil {
			debug("Error accepting: ", err.Error())
			continue
		}

		uuu := shortuuid.New()
		debugf("new suuid: %q", uuu)
		newClient := Client{
			Conn:      conn,
			PublicKey: server.Config.Client.PublicKey,
			Id:        uuu,
		}
		server.AddClient(newClient)

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
					fmt.Println(err)
				}
			}
		}(server)

		// Handle connections in a new goroutine.
		go server.handleConnectionFromClient(uuu)
	}
}

func (s *DistribServer) AddClient(newClient Client) error {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.clients[newClient.Id]; ok {
		return fmt.Errorf("Client with id %v already exists", newClient.Id)
	}

	s.clients[newClient.Id] = newClient

	return nil
}

func (s *DistribServer) ClientById(uuu string) (*Client, error) {
	s.Lock()
	defer s.Unlock()

	if c, ok := s.clients[uuu]; ok {
		return &c, nil
	}
	return &Client{}, fmt.Errorf("Client with id %v does not exists", uuu)
}

func (server *DistribServer) handleConnectionFromClient(uuu string) error {

	var client *Client
	var conn net.Conn
	var err error
	client, err = server.ClientById(uuu)
	if err != nil {
		return err
	}
	conn = client.Conn

	defer func(conn net.Conn) {
		debug(conn.LocalAddr(), conn.RemoteAddr())
		defer delete(server.clients, uuu)
		conn.Close()
	}(conn)

	for {
		reader := bufio.NewReader(conn)
		buf, isPrefix, err := reader.ReadLine()

		if err != nil {
			fmt.Println(fmt.Sprintf("Error reading (server): %v", err.Error()))
			conn.Close()
			break
		}

		if !isPrefix && len(buf) > 0 {
			// Create Job and push the work onto the jobQueue.
			debug("received job blob")
			job := Job{
				Name: "some server job",
				uuu:  uuu,
				buf:  buf,
			}
			server.jobQueue <- job
		}
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////

func (server *DistribServer) runDispatcher() {
	for i := 0; i < server.dispatcher.maxWorkers; i++ {
		worker := NewWorker(i+1, server.dispatcher.workerPool)
		debug("starting worker.startWithServer(server)")
		worker.startWithServer(server)
		debug("started worker.startWithServer(server)")
	}

	go server.dispatcher.dispatch()
}

func (w Worker) startWithServer(server *DistribServer) {
	go func() {
		for {
			debug("startWithServer")
			// Add my jobQueue to the worker pool.
			w.workerPool <- w.jobQueue

			select {
			case job := <-w.jobQueue:
				// Dispatcher has added a job to my jobQueue.
				debug("started job")

				server.handleMessageFromClient(job.uuu, job.buf)

				debug("job completed")
			case <-w.quitChan:
				// We have been asked to stop.
				fmt.Printf("worker%d stopping\n", w.id)
				return
			}
		}
	}()
}

///////////////////////////////////////////////////////////////////////////

func (server *DistribServer) handleMessageFromClient(uuu string, buf []byte) {
	debug("received len:", len(buf))
	debugf("%v#\n", string(buf))

	metaPack, err := decodeMetaPack(buf)
	if err != nil {
		debug("SERVER", err)
		return
	}

	/*
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

func (server *DistribServer) On(funcName string, callback interface{}) error {
	if _, ok := server.callbacks[funcName]; ok {
		panic(fmt.Sprintf("Callback name %q already existing; please choose a different one", funcName))
	}

	server.callbacks[funcName] = callback
	return nil
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

func (server *DistribServer) Request(uuu string, metaPack MetaPack) (interface{}, error) {

	if _, ok := server.callbacks[string(metaPack.Pack.Destination)]; !ok {
		return "", fmt.Errorf("Callback %q does not exist", string(metaPack.Pack.Destination))
	}

	cc, err := server.newContext(uuu, metaPack.Pack)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	switch server.callbacks[string(metaPack.Pack.Destination)].(type) {
	case func(Context) (interface{}, error):
		{
			fmt.Println("in Trigger, type is func(Context) (interface{}, error)")
			data, err := server.callbacks[string(metaPack.Pack.Destination)].(func(Context) (interface{}, error))(cc)
			fmt.Println("in Trigger, data, err:=", data, err)
			return data, err
		}
	}
	return "", fmt.Errorf("Callback %q is not of right format (%#v instead of func(Context) (interface{}, error))", string(metaPack.Pack.Destination), server.callbacks[string(metaPack.Pack.Destination)])
}

func (server *DistribServer) CountClients() int {
	return len(server.clients)
}
