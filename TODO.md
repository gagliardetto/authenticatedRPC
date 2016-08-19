## TODO

+ test when I have alpha
+ Use see http://marcio.io/2015/07/handling-1-million-requests-per-minute-with-golang/ fot the handleServerRequest/handleClientRequest
+ Risolvere i memory leak
+ instance.Close()
+ longer tcp message size (prefix message with size, and then reader.Read(size) ???)
+ Special event types, or instance.OnOpen(...) ???
+ OnOpen, OnClose, OnError, OnMessage
+ Find better unique id for client connections (int32 ???)
+ Distinguere tra frame e messaggi (1 messaggio = uno o più frame)
+ binary messages
+ message compression (lz4 ???)
+ [x] server.Run("127.0.0.1:3333")//server and client.Connect("127.0.0.1:3333")//client
+ ✗Context.Conn -> Context.conn (make private)
+ [x] TLS
+ [x] Authentication (certs)
+ [x] instance.Config{}
+ [x] DistribServer.clients[0] = client{conn net.Conn, } 
+ [x] InsecureSkipVerify ??? (see connection to mongodb)
+ [x] tls.Dial (from client to server) with cert or without ??? : With cert, that is verified server-side.
+ ✗✗message encryption (encryption is handled by TLS)
+ [x] panic on duplicate callback name
+ distinguere bene tra pubblico e privato

	[x] tls.Dial("tcp", addr.String(), &tls.Config{
					ServerName: "www.mongodirector.com",
					//InsecureSkipVerify: false,
					RootCAs: mongoCertPool,
				})
	https://golang.org/pkg/crypto/tls/#example_Dial


+ [x] .Trigger, .Receive
+ ✗✗send to all (from server)
+ ✗✗send to by id (server.To(id).Send(Pack) )

+ [x] reconnect
+ [x] remove rsa signing and encryption
+ [x] il .Receive() restituisce un valore e un errore
+ [x] scaricare tutti gli archivi, decomprimerli in /dev/null e contare i byte
+ Ping pong to keep alive the connection ?
+ heartbeat
+ [x] TLS by default
+ `server.DisableTLS = true` instead of `server.EnableTLS = false`
+ handle handleServerMessage handleClientMessage errors (in a channel ???)
+ reduce dependence on strings
+ check existence of elements inside structs before using
+ alternative to `go server.handleConnectionFromClient(uuu)`
+ spostare creazione di un Context prima rispetto a dove è adesso
+ il .ContinuousReceive() restituisce un channel e un errore
+ inside encodeAndSendMetaPack() check whether all the necessary fields have been set and are valid

+ sicurezza concurrent r/w access to data
+ callOk, requestOk etc.
+ close
+ sessions
