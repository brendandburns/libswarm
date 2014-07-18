package backends

import (
	"io/ioutil"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/docker/libswarm"

	"code.google.com/p/go.crypto/ssh"
)

const (
	testSSHListenAddr = "127.0.0.1:2022"
	testSSHPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALdGZxkXDAjsYk10ihwU6Id2KeILz1TAJuoq4tOgDWxEEGeTrcld
r/ZwVaFzjWzxaf6zQIJbfaSEAhqD5yo72+sCAwEAAQJBAK8PEVU23Wj8mV0QjwcJ
tZ4GcTUYQL7cF4+ezTCE9a1NrGnCP2RuQkHEKxuTVrxXt+6OF15/1/fuXnxKjmJC
nxkCIQDaXvPPBi0c7vAxGwNY9726x01/dNbHCE0CBtcotobxpwIhANbbQbh3JHVW
2haQh4fAG5mhesZKAGcxTyv4mQ7uMSQdAiAj+4dzMpJWdSzQ+qGHlHMIBvVHLkqB
y2VdEyF7DPCZewIhAI7GOI/6LDIFOvtPo6Bj2nNmyQ1HU6k/LRtNIXi4c9NJAiAr
rrxx26itVhJmcvoUhOjwuzSlP2bE5VHAvkGB352YBg==
-----END RSA PRIVATE KEY-----
`
)

func TestSSHTunnelSpawn(t *testing.T) {
	chanchan := make(chan (<-chan ssh.NewChannel))
	go func() {
		config := &ssh.ServerConfig{
			PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				log.Println("discarding key based auth")
				return nil, nil
			},
		}
		listener, err := net.Listen("tcp", testSSHListenAddr)
		if err != nil {
			t.Fatalf("failed to listen on %q: %v", testSSHListenAddr, err)
		}
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("failed to accept incoming connect: %v", err)
		}
		log.Println("tunnel: test: new client")

		key, err := ssh.ParsePrivateKey([]byte(testSSHPrivateKey))
		if err != nil {
			t.Fatalf("failed to parse host key")
		}
		config.AddHostKey(key)

		_, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			t.Fatalf("hanshaked failed: %v", err)
		}
		log.Println("tunnel: test: handshake succeeded")
		go ssh.DiscardRequests(reqs)
		chanchan <- chans
	}()
	tunnel := SSHTunnel()
	tunnelClient := libswarm.AsClient(tunnel)
	tmpKey, err := ioutil.TempFile("", "libswarm-tunnel-test-empty-key")
	if err != nil {
		t.Fatalf("failed to create temporary key: %v", err)
	}
	defer tmpKey.Close()
	tmpKey.WriteString(testSSHPrivateKey)
	dockerClient, err := tunnelClient.Spawn(testSSHListenAddr, tmpKey.Name())
	if err != nil {
		t.Fatalf("failed to spawn tunnel backend: %v", err)
	}
	go dockerClient.Ls()
	chans := <-chanchan
	newChan := <-chans
	log.Printf("tunnel: test: got newchan:%q", newChan.ChannelType())
	if newChan.ChannelType() != "direct-tcpip" {
		t.Fatalf("expected tunneling with newchan:direct-tcpip, got %q", newChan.ChannelType())
	}
}

func TestSSHTunnelSpawnBadArgs(t *testing.T) {
	if _, err := libswarm.AsClient(SSHTunnel()).Spawn(); err == nil || !strings.Contains(err.Error(), "arguments") {
		t.Fatalf("expected args error, got %q", err)
	}
	if _, err := libswarm.AsClient(SSHTunnel()).Spawn("bad-connection-string", ""); err == nil || !strings.Contains(err.Error(), "connection") {
		t.Fatalf("expected connection error, got %q", err)
	}
	if _, err := libswarm.AsClient(SSHTunnel()).Spawn(testSSHListenAddr, "/unlikely-to-exists"); err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("expected key error, got %q", err)
	}
}
