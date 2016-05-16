package main

import (
	_ "bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

var err error
var newKeySetFolderName string

func main() {

	if _, err := os.Stat("key-sets"); err != nil {
		if os.IsNotExist(err) {
			err = os.Mkdir("key-sets", 0700)
			if err != nil {
				fmt.Println("Failed to create 'key-sets' directory:", err)
				os.Exit(1)
			}
		}
	}

	newKeySetFolderName = "key-set-" + fmt.Sprint(time.Now().Format("15.04.05 2006-01-02 CET"))

	err = os.Mkdir("key-sets/"+newKeySetFolderName, 0700)
	if err != nil {
		fmt.Println("Failed to create 'key-sets' directory:", err)
		os.Exit(1)
	}

	err = os.Mkdir("key-sets/"+newKeySetFolderName+"/keys-for-server", 0700)
	if err != nil {
		fmt.Println("Failed to create '/keys-for-server' directory:", err)
		os.Exit(1)
	}

	err = os.Mkdir("key-sets/"+newKeySetFolderName+"/keys-for-client", 0700)
	if err != nil {
		fmt.Println("Failed to create '/keys-for-client' directory:", err)
		os.Exit(1)
	}

	generateClientKeys()

	generateServerKeys()

	fmt.Println("Keys have been generated. You can find them here:")
	fmt.Println("./key-sets/" + newKeySetFolderName)
}

func generateServerKeys() {
	serverCRTTemplate := x509.Certificate{
		Subject: pkix.Name{
			//Organization: []string{"org name"},
			CommonName: "distributed.server",
		},
		NotBefore: time.Now(),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IsCA: true,
		// DNSNames:
		// IPAddresses:
	}

	serverCRTTemplate.NotAfter = serverCRTTemplate.NotBefore.Add(time.Duration(365) * time.Hour * 24)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serverCRTTemplate.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Println("Failed to generate serial number:", err)
		os.Exit(1)
	}

	serverPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		os.Exit(1)
	}

	serverCRTBytes, err := x509.CreateCertificate(rand.Reader, &serverCRTTemplate, &serverCRTTemplate, &serverPrivate.PublicKey, serverPrivate)
	if err != nil {
		fmt.Println("Failed to create certificate:", err)
		os.Exit(1)
	}

	serverCRTOut, err := os.OpenFile("key-sets/"+newKeySetFolderName+"/keys-for-server/server.public.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Failed to open server.public.crt for writing:", err)
		os.Exit(1)
	}
	pem.Encode(serverCRTOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverCRTBytes})

	cp("key-sets/"+newKeySetFolderName+"/keys-for-client/server.public.crt", "key-sets/"+newKeySetFolderName+"/keys-for-server/server.public.crt")

	serverCRTOut.Close()

	serverKeyOut, err := os.OpenFile("key-sets/"+newKeySetFolderName+"/keys-for-server/server.private.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("failed to open server.private.key for writing:", err)
		os.Exit(1)
	}
	pem.Encode(serverKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivate)})
	serverKeyOut.Close()
}

func generateClientKeys() {
	clientCRTTemplate := x509.Certificate{
		Subject: pkix.Name{
			//Organization: []string{"org name"},
			CommonName: "distributed.client",
		},
		NotBefore: time.Now(),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,

		IsCA: true,
		// DNSNames:
		// IPAddresses:
	}

	clientCRTTemplate.NotAfter = clientCRTTemplate.NotBefore.Add(time.Duration(365) * time.Hour * 24)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	clientCRTTemplate.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Println("Failed to generate serial number:", err)
		os.Exit(1)
	}

	clientPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		os.Exit(1)
	}

	clientCRTBytes, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, &clientCRTTemplate, &clientPrivate.PublicKey, clientPrivate)
	if err != nil {
		fmt.Println("Failed to create certificate:", err)
		os.Exit(1)
	}

	clientCRTOut, err := os.OpenFile("key-sets/"+newKeySetFolderName+"/keys-for-client/client.public.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Failed to open client.public.crt for writing:", err)
		os.Exit(1)
	}
	pem.Encode(clientCRTOut, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTBytes})

	cp("key-sets/"+newKeySetFolderName+"/keys-for-server/client.public.crt", "key-sets/"+newKeySetFolderName+"/keys-for-client/client.public.crt")
	clientCRTOut.Close()

	clientKeyOut, err := os.OpenFile("key-sets/"+newKeySetFolderName+"/keys-for-client/client.private.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("failed to open client.private.key for writing:", err)
		os.Exit(1)
	}
	pem.Encode(clientKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivate)})
	clientKeyOut.Close()
}

func cp(dst, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	// no need to check errors on read only file, we already got everything
	// we need from the filesystem, so nothing can go wrong now.
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}
