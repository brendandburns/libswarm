package backends

import (
	"io/ioutil"
	"log"
	"net"
	"os/user"
	"strings"
	"testing"

	"github.com/docker/libswarm"

	"code.google.com/p/go.crypto/ssh"
)

const (
	testSSHListenAddr = "127.0.0.1:2022"
	testSSHUser       = "test-ssh-user"
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

func TestSSHTunnelClient(t *testing.T) {
	// start a ssh server
	conns := make(chan ssh.ConnMetadata)
	chanchan := make(chan (<-chan ssh.NewChannel))
	go func() {
		config := &ssh.ServerConfig{
			PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				log.Println("discarding key based auth")
				conns <- c
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

	// create the libswarm backend
	tunnel := SSHTunnel()
	tunnelClient := libswarm.AsClient(tunnel)
	tmpKey, err := ioutil.TempFile("", "libswarm-tunnel-test-empty-key")
	if err != nil {
		t.Fatalf("failed to create temporary key: %v", err)
	}
	defer tmpKey.Close()
	tmpKey.WriteString(testSSHPrivateKey)

	// spawnn the docker client from the backend and call Ls verb.
	go func() {
		dockerClient, err := tunnelClient.Spawn("testuser@"+testSSHListenAddr, tmpKey.Name())
		if err != nil {
			t.Fatalf("failed to spawn tunnel backend: %v", err)
		}
		dockerClient.Ls()
	}()

	// validate username
	conn := <-conns
	if conn.User() != "testuser" {
		t.Errorf("execpeted user: %q, got %q", "testuser", conn.User())
	}

	// validate tunnel conn
	chans := <-chanchan
	newChan := <-chans
	log.Printf("tunnel: test: got newchan:%q", newChan.ChannelType())
	if newChan.ChannelType() != "direct-tcpip" {
		t.Fatalf("expected tunneled connection with newchan:direct-tcpip, got %q", newChan.ChannelType())
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

func TestParserSSHConnectionString(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}
	connTests := []struct {
		conn string
		user string
		addr string
		err  bool
	}{
		{"foo@bar:22", "foo", "bar:22", false},
		{"bar:22", usr.Username, "bar:22", false},
		{"bar", "", "", true},
	}
	for _, ct := range connTests {
		u, a, err := parseSSHConnectionString(ct.conn)
		if ct.err != (err != nil) {
			t.Errorf("expectxed err: %q, got %q", ct.err, err)
			continue
		}
		if ct.user != u {
			t.Errorf("expected user: %q, got %q", ct.user, u)
		}
		if ct.addr != a {
			t.Errorf("expected addr: %q, got %q", ct.addr, u)
		}
	}
}
