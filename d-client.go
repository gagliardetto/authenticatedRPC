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
)

type (
	DistribClient struct {
		callbacks map[string]interface{}
		Conn      net.Conn
		channels  FlowChannels

		dispatcher   *Dispatcher
		jobQueue     chan Job
		maxWorkers   int
		maxQueueSize int

		Config ClientConfig
	}

	ClientConfig struct {
		DisableTLS bool
		Cert       tls.Certificate
		PrivateKey *rsa.PrivateKey
		Server     struct {
			VerifyCert bool
			Name       string
			CertPath   string
			PublicKey  *rsa.PublicKey
			address    *net.TCPAddr
		}
	}
)

func NewClient() DistribClient {
	var newClient DistribClient
	newClient.callbacks = make(map[string]interface{})
	newClient.channels = FlowChannels{}
	newClient.channels.Channels = make(ChannelMap)

	newClient.maxWorkers = 5
	newClient.maxQueueSize = 100

	return newClient
}

func (client *DistribClient) Connect(indirizzo string) error {
	var conn net.Conn
	var err error

	// Create the job queue.
	client.jobQueue = make(chan Job, client.maxQueueSize)

	// Start the dispatcher.
	client.dispatcher = NewDispatcher(client.jobQueue, client.maxWorkers)
	client.runDispatcher()

	client.Config.Server.address, err = net.ResolveTCPAddr("tcp", indirizzo)
	if err != nil {
		return err
	}

	if client.Config.DisableTLS {

		conn, err = net.Dial("tcp", client.Config.Server.address.String())
		if err != nil {
			return fmt.Errorf("Error connectting plain text:", err.Error())
		}
		debug("Connected via plain text conn. to " + client.Config.Server.address.String())

	} else {

		if len(client.Config.Cert.Certificate) < 1 {
			panic("SSL is enabled, but no certificate was provided. Please provide a certificate (recommended) or disable SSL")
		}

		var serverCertPool *x509.CertPool

		if client.Config.Server.VerifyCert {

			serverCertPool = x509.NewCertPool()

			serverCert, err := ioutil.ReadFile(client.Config.Server.CertPath)
			if err != nil {
				panic(fmt.Sprintf("Can't open/find server certificate: %q", err))
			}

			if ok := serverCertPool.AppendCertsFromPEM([]byte(serverCert)); !ok {
				panic("Failed to append server certificate to pool")
			}
		}

		clientTLSconfig := tls.Config{
			ServerName:   client.Config.Server.Name,
			Certificates: []tls.Certificate{client.Config.Cert},
			RootCAs:      serverCertPool,

			InsecureSkipVerify: false,
		}
		clientTLSconfig.Rand = rand.Reader

		conn, err = tls.Dial("tcp", client.Config.Server.address.String(), &clientTLSconfig)
		if err != nil {
			return fmt.Errorf("Error connecting via TLS: %v", err.Error())
		}
		debug("Connected via TLS to " + client.Config.Server.address.String())
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
		debug(conn.LocalAddr(), conn.RemoteAddr())
		conn.Close()
		client.Conn = nil
	}(conn)

	for {
		reader := bufio.NewReader(conn)
		buf, isPrefix, err := reader.ReadLine()

		if err != nil {
			fmt.Println(fmt.Sprintf("Error reading (client): %v", err.Error()))
			conn.Close()
			break
		}

		if !isPrefix && len(buf) > 0 {
			debug("received job blob")
			// Create Job and push the work onto the jobQueue.
			job := Job{
				Name: "some client job",
				buf:  buf,
			}
			client.jobQueue <- job
		}
	}
}

///////////////////////////////////////////////////////////////////////////////

func (client *DistribClient) runDispatcher() {
	for i := 0; i < client.dispatcher.maxWorkers; i++ {
		worker := NewWorker(i+1, client.dispatcher.workerPool)
		worker.startWithClient(client)
	}

	go client.dispatcher.dispatch()
}

func (w Worker) startWithClient(client *DistribClient) {
	go func() {
		for {
			debug("startWithClient")
			// Add my jobQueue to the worker pool.
			w.workerPool <- w.jobQueue

			select {
			case job := <-w.jobQueue:
				// Dispatcher has added a job to my jobQueue.
				debug("started job")

				client.handleMessageFromServer(job.buf)

				debug("job completed")
			case <-w.quitChan:
				// We have been asked to stop.
				fmt.Printf("worker%d stopping\n", w.id)
				return
			}
		}
	}()
}

///////////////////////////////////////////////////////////////////////////////

func (client *DistribClient) handleMessageFromServer(buf []byte) {
	debug("received len:", len(buf))
	debugf("%v#\n", string(buf))

	metaPack, err := decodeMetaPack(buf)
	if err != nil {
		debug("CLIENT", err)
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

func (client *DistribClient) Request(metaPack MetaPack) (interface{}, error) {

	if _, ok := client.callbacks[string(metaPack.Pack.Destination)]; !ok {
		return "", fmt.Errorf("Callback %q does not exist", string(metaPack.Pack.Destination))
	}

	cc, err := client.newContext(metaPack.Pack)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	switch client.callbacks[string(metaPack.Pack.Destination)].(type) {
	case func(Context) (interface{}, error):
		{
			fmt.Println("in Trigger, type is func(Context) (interface{}, error)")
			data, err := client.callbacks[string(metaPack.Pack.Destination)].(func(Context) (interface{}, error))(cc)
			fmt.Println("in Trigger, data, err:=", data, err)
			return data, err
		}
	}
	return "", fmt.Errorf("Callback %q is not of right format (%#v instead of func(Context) (interface{}, error))", string(metaPack.Pack.Destination), client.callbacks[string(metaPack.Pack.Destination)])
}

func (client *DistribClient) On(funcName string, callback interface{}) error {
	if _, ok := client.callbacks[funcName]; ok {
		panic(fmt.Sprintf("Callback name %q already existing; please choose a different one", funcName))
	}

	switch callback.(type) {
	case func(Context):
		{
			break
		}
	case func(Context) (interface{}, error):
		{
			break
		}
	default:
		{
			panic(fmt.Sprintf("Callback %q type is not supported; use %q or %q.", funcName, "func(Context){}", "func(Context) (interface{}, error){}"))
		}
	}

	client.callbacks[funcName] = callback
	return nil
}
