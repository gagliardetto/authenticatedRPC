# Distributed_workers

## Description

TLS-encrypted TCP-based real-time bidirectional authenticated messaging.

## Installation

```
go get -u github.com/gagliardetto/distributed_workers
```

## Getting Started

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