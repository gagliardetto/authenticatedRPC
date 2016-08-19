package authenticatedRPC

import (
	"bufio"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/renstrom/shortuuid"
	"github.com/ugorji/go/codec"
)

var Debugging bool = true

const (
	ConnectEvent string = "DefaultConnectEvent"
	//onopen
	//onclose
	//onerror
	//onmessage

	//url
	//readyState (CONNECTING, OPEN, CLOSING, CLOSED)

	//.Close()

	triggerCallType   string = "triggerCallType"
	triggerAnswerType string = "triggerAnswerType"
	requestCallType   string = "requestCallType"
	requestAnswerType string = "requestAnswerType"

	requestMaxDuration time.Duration = time.Minute * 10
)

type (
	Context struct {
		Data   Pack
		Conn   net.Conn
		Local  Local
		Remote Remote
	}
	Local struct {
		PrivateKey *rsa.PrivateKey
		channels   *FlowChannels
	}
	Remote struct {
		PublicKey *rsa.PublicKey
	}

	Pack struct {
		Destination string
		Payload     interface{}
		Error       error
		IssueDate   time.Time
	}

	MetaPack struct {
		Pack      Pack
		Hash      []byte
		Signature []byte
		CallID    string
		answerID  string
		Type      string
	}

	CallbackOfTrigger func(Context)
	CallbackOfReceive func(Context) (interface{}, error)

	FlowChannels struct {
		Channels ChannelMap
		sync.RWMutex
	}
	ChannelMap map[string]*FlowChannel

	FlowChannel struct {
		Channel      chan Pack
		CreationDate time.Time
	}
)

func (cc *Context) Trigger(messagePack Pack) error {
	ID := shortuuid.New()
	metaPack := &MetaPack{
		Pack:   messagePack,
		CallID: ID,
		Type:   triggerCallType,
	}
	err := cc.compileAndSendMetaPack(metaPack)
	if err != nil {
		return err
	}
	return nil
}

func (cc *Context) Receive(messagePack Pack) (Pack, error) {
	ID := shortuuid.New()
	channel := make(chan Pack)

	// Check if ID does not exist yet?

	cc.Local.channels.Lock()
	cc.Local.channels.Channels[ID] = &FlowChannel{}
	cc.Local.channels.Channels[ID].Channel = channel
	cc.Local.channels.Unlock()
	debug("===QUI===")

	defer close(cc.Local.channels.Channels[ID].Channel)

	metaPack := &MetaPack{
		Pack:   messagePack,
		CallID: ID,
		Type:   requestCallType,
	}

	err := cc.compileAndSendMetaPack(metaPack)
	if err != nil {
		return Pack{}, err
	}

	var responsePack Pack
	select {
	case responsePack = <-cc.Local.channels.Channels[ID].Channel:
		{
			debug("new received:", responsePack)
			return responsePack, nil
		}
	case <-time.After(requestMaxDuration):
		return responsePack, fmt.Errorf("channel timeout")
	}
}

func (cc *Context) compileAndSendMetaPack(metaPack *MetaPack) error {
	metaPack.Pack.IssueDate = time.Now()

	encodedMessagePack, err := metaPack.Pack.encode()
	if err != nil {
		return err
	}
	encodedMessagePackHash := hash(encodedMessagePack)

	metaPack.Hash = encodedMessagePackHash

	encodedMetaPack, err := metaPack.encode()
	if err != nil {
		return err
	}
	debug("sending # bytes:", len(encodedMetaPack))
	encodedMetaPack = append(encodedMetaPack[:], []byte("\r\n")[:]...)
	_, err = cc.Conn.Write(encodedMetaPack)
	if err != nil {
		return err
	}

	return nil
}

func (message *Pack) encode() ([]byte, error) {
	var encoded []byte = make([]byte, 0, 64)
	var h codec.Handle = new(codec.JsonHandle)
	var enc *codec.Encoder = codec.NewEncoderBytes(&encoded, h)
	var err error = enc.Encode(message)
	if err != nil {
		return nil, fmt.Errorf("Error encoding pack: %s", err.Error())
	}
	return encoded, nil
}
func (metaPack *MetaPack) encode() ([]byte, error) {
	var encoded []byte = make([]byte, 0, 64)
	var h codec.Handle = new(codec.JsonHandle)
	var enc *codec.Encoder = codec.NewEncoderBytes(&encoded, h)
	var err error = enc.Encode(metaPack)
	if err != nil {
		return nil, fmt.Errorf("Error encoding metaPack: %s", err.Error())
	}
	return encoded, nil
}

func (metaPack *MetaPack) encoder(conn net.Conn) error {
	var writer *bufio.Writer
	writer = bufio.NewWriter(conn)

	var h codec.Handle = new(codec.JsonHandle)
	var enc *codec.Encoder = codec.NewEncoder(writer, h)

	var err error = enc.Encode(metaPack)
	if err != nil {
		return fmt.Errorf("Error encoding metaPack: %s", err.Error())
	}
	return nil
}

func decodePack(message []byte) (Pack, error) {
	var decoded Pack
	var h codec.Handle = new(codec.JsonHandle)
	var dec *codec.Decoder = codec.NewDecoderBytes(message, h)
	var err error = dec.Decode(&decoded) // must be a pointer
	if err != nil {
		return Pack{}, fmt.Errorf("Error decoding pack: %s", err.Error())
	}
	return decoded, nil
}
func decodeMetaPack(message []byte) (MetaPack, error) {
	var decoded MetaPack
	var h codec.Handle = new(codec.JsonHandle)
	var dec *codec.Decoder = codec.NewDecoderBytes(message, h)
	var err error = dec.Decode(&decoded) // must be a pointer
	if err != nil {
		return MetaPack{}, fmt.Errorf("Error decoding metaPack: %s", err.Error())
	}
	return decoded, nil
}

func decoder(conn net.Conn) (MetaPack, error) {
	var reader *bufio.Reader
	reader = bufio.NewReader(conn)

	var decoded MetaPack
	var h codec.Handle = new(codec.JsonHandle)
	var dec *codec.Decoder = codec.NewDecoder(reader, h)
	var err error = dec.Decode(&decoded) // must be a pointer
	if err != nil {
		return MetaPack{}, fmt.Errorf("Error decoding metaPack: %s", err.Error())
	}
	return decoded, nil
}

func (cc *Context) encrypt(encodedMessagePack []byte) ([]byte, error) {
	// I am sender.
	// message to encrypt; recipient's public key;

	label := []byte("")

	encryptedMessagePack, err := rsa.EncryptOAEP(md5.New(), rand.Reader, cc.Remote.PublicKey, encodedMessagePack, label)

	if err != nil {
		return []byte{}, err
	}

	return encryptedMessagePack, nil
}

func (cP *MetaPack) decrypt(recipientPrivateKey *rsa.PrivateKey) ([]byte, error) {
	// I am recipient.
	// encrypted text; my private key;

	label := []byte("")

	encodedPack, err := cP.Pack.encode()
	if err != nil {
		return []byte{}, err
	}

	packBytes, err := rsa.DecryptOAEP(md5.New(), rand.Reader, recipientPrivateKey, encodedPack, label)

	if err != nil {
		return []byte{}, err
	}

	return packBytes, nil
}

func (cc *Context) sign(bytesToSign []byte) ([]byte, error) {
	// I am sender.
	// encrypted message; hash of the encrypted message; my private key;

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	pssh := crypto.MD5.New()
	pssh.Write(bytesToSign)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, cc.Local.PrivateKey, crypto.MD5, hashed, &opts)

	if err != nil {
		return []byte{}, err
	}

	return signature, nil
}

func (cP *MetaPack) verify_signature(senderPublicKey *rsa.PublicKey) error {
	// I am recipient.
	// sender's public key; hash of the encrypted message; signed message;

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	pssh := crypto.MD5.New()

	encodedPack, err := cP.Pack.encode()
	if err != nil {
		return err
	}

	pssh.Write(encodedPack)
	hashed := pssh.Sum(nil)

	//Verify Signature
	err = rsa.VerifyPSS(senderPublicKey, crypto.MD5, hashed, cP.Signature, &opts)

	if err != nil {
		return err
	} else {
		return nil
	}

}

func generate_rsa_keys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var private_key *rsa.PrivateKey
	var public_key *rsa.PublicKey
	var err error

	//Generate Private Key
	if private_key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return &rsa.PrivateKey{}, &rsa.PublicKey{}, err
	}
	fmt.Println(private_key)

	// Precompute some calculations -- Calculations that speed up private key operations in the future
	private_key.Precompute()

	//Validate Private Key -- Sanity checks on the key
	if err = private_key.Validate(); err != nil {
		return &rsa.PrivateKey{}, &rsa.PublicKey{}, err
	}

	//Public key address (of an RSA key)
	public_key = &private_key.PublicKey

	return private_key, public_key, nil
}

func load_rsa_keys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// A PEM file can contain a Private key among others (Public certificate, Intermidiate Certificate, Root certificate, ...)
	pem_file_path := "/path/to/pem/file"
	pem_data, err := ioutil.ReadFile(pem_file_path)
	if err != nil {
		return &rsa.PrivateKey{}, &rsa.PublicKey{}, fmt.Errorf("Error reading pem file: %s", err)
	}

	//Package pem implements the PEM data encoding, most commonly used in TLS keys and certificates.
	//Decode will find the next PEM formatted block (certificate, private key etc) in the input.
	//Expected Block type "RSA PRIVATE KEY"
	//http://golang.org/pkg/encoding/pem/

	block, _ := pem.Decode(pem_data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return &rsa.PrivateKey{}, &rsa.PublicKey{}, fmt.Errorf("No valid PEM data found: %s", block.Type)
	}

	//x509 parses X.509-encoded keys and certificates.
	//ParsePKCS1PrivateKey returns an RSA private key from its ASN.1 PKCS#1 DER encoded form.
	private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return &rsa.PrivateKey{}, &rsa.PublicKey{}, fmt.Errorf("Private key can't be decoded: %s", err)
	}

	public_key := &private_key.PublicKey

	return private_key, public_key, nil
}

func LoadPrivateKey(pem_file_path string) (*rsa.PrivateKey, error) {
	pem_data, err := ioutil.ReadFile(pem_file_path)
	if err != nil {
		return &rsa.PrivateKey{}, fmt.Errorf("Error reading pem file: %s", err)
	}

	block, _ := pem.Decode(pem_data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return &rsa.PrivateKey{}, fmt.Errorf("No valid PEM data found: %s", block.Type)
	}

	//x509 parses X.509-encoded keys and certificates.
	//ParsePKCS1PrivateKey returns an RSA private key from its ASN.1 PKCS#1 DER encoded form.
	private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return &rsa.PrivateKey{}, fmt.Errorf("Private key can't be decoded: %s", err)
	}

	return private_key, nil
}

func LoadPublicKey(pem_file_path string) (*rsa.PublicKey, error) {
	pem_data, err := ioutil.ReadFile(pem_file_path)
	if err != nil {
		return &rsa.PublicKey{}, fmt.Errorf("Error reading pem file: %s", err)
	}

	block, _ := pem.Decode(pem_data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return &rsa.PublicKey{}, fmt.Errorf("No valid PEM data found: %s", block.Type)
	}

	public_key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return &rsa.PublicKey{}, fmt.Errorf("Public key can't be decoded: %s", err)
	}

	_, ok := public_key.(*rsa.PublicKey)
	if !ok {
		return &rsa.PublicKey{}, fmt.Errorf("not an RSA public key")
	}

	return public_key.(*rsa.PublicKey), nil
}

func hash(bytesToHash []byte) []byte {
	hasher := crypto.MD5.New()
	hasher.Write(bytesToHash)
	hash := hasher.Sum(nil)
	return hash
	//base64hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func debugf(format string, a ...interface{}) (n int, err error) {
	if Debugging {
		return fmt.Println(fmt.Sprintf(format, a...))
	}
	return 0, nil
}
func debug(a ...interface{}) (n int, err error) {
	if Debugging {
		return fmt.Println(a...)
	}
	return 0, nil
}

/////////////////////////////////////////////////////////////////////////////////////////

// Job holds the attributes needed to perform unit of work.
type Job struct {
	Name string
	uuu  string
	buf  []byte
}

// NewWorker creates takes a numeric id and a channel w/ worker pool.
func NewWorker(id int, workerPool chan chan Job) Worker {
	return Worker{
		id:         id,
		jobQueue:   make(chan Job),
		workerPool: workerPool,
		quitChan:   make(chan bool),
	}
}

type Worker struct {
	id         int
	jobQueue   chan Job
	workerPool chan chan Job
	quitChan   chan bool
}

func (w Worker) stop() {
	go func() {
		w.quitChan <- true
	}()
}

// NewDispatcher creates, and returns a new Dispatcher object.
func NewDispatcher(jobQueue chan Job, maxWorkers int) *Dispatcher {
	workerPool := make(chan chan Job, maxWorkers)

	return &Dispatcher{
		jobQueue:   jobQueue,
		maxWorkers: maxWorkers,
		workerPool: workerPool,
	}
}

func (d *Dispatcher) dispatch() {
	for {
		select {
		case job := <-d.jobQueue:
			go func() {
				fmt.Printf("fetching workerJobQueue for: %s\n", job.Name)
				workerJobQueue := <-d.workerPool
				fmt.Printf("adding %s to workerJobQueue\n", job.Name)
				workerJobQueue <- job
			}()
		}
	}
}

type Dispatcher struct {
	workerPool chan chan Job
	maxWorkers int
	jobQueue   chan Job
}
