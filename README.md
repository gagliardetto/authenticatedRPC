# authenticatedRPC

## Description

TLS-encrypted TCP-based real-time bidirectional authenticated RPC.

## Installation

```
go get -u github.com/gagliardetto/authenticatedRPC
```

## How it works

Trigger (a call without response payload):

```go
instance.On("autoDestruction", func(cc dis.Context) {
	// ...
})
```

Receive (a call that returns a payload):

```go
instance.On("myNameIs", func(cc dis.Context) (interface{}, error) {
	return "Tony Stark", nil
})
```

How to call a trigger:

```go
instance.On("something", func(cc dis.Context) {
	triggerPack := dis.Pack{
		Destination: "autoDestruction",
		Payload:     "Not this time",
	}
	err := cc.Trigger(triggerPack)
	if err != nil {
		fmt.Println(err)
	}
})
```

How to call a Receive:

```go
instance.On("something", func(cc dis.Context) {
	requestPack := dis.Pack{
		Destination: "myNameIs",
		Payload:     "I'd like to know you.",
	}
	responsePack, err := cc.Receive(requestPack)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Awesome to meet you,", responsePack.Payload.(string))
})
```


## Generate keys

Enter `distributed-workers-example` and run the `gen-keys.go` script to generate the keys:

```
$ cd distributed-workers-example
$ go run gen-keys.go
```

The newly-generated keys are inside a timestamped folder inside `key-sets` folder.

Copy `keys-for-client` inside the `client` folder; and `keys-for-server` inside the `server` folder.

Now you are ready to go to run the example.

Enter the `server` folder and run `server.go`

```
$ cd server
$ go run server.go
```

Now open another terminal tab/window, enter the `client` folder and run `client.go`.

```
$ cd client
$ go run client.go
```

The client will connect to the server and start a ping-pong match.
