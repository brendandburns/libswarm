//
// Copyright (C) 2014 The Docker Cloud authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package backends

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strings"

	"code.google.com/p/go.crypto/ssh"
	"github.com/docker/libswarm"
)

const (
	usage      = "tunnel ip:port /path/to/ssh/key"
	dockerHost = "127.0.0.1:4243"
)

// newSSHKey Read parses a private SSH key.
func newSSHKey(path string) (ssh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to load ssh key from %q: %v", path, err)
	}
	defer f.Close()

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read ssh key: %v", err)
	}
	return ssh.ParsePrivateKey(bs)
}

// sshDialer is a ssh tunnel connection dialer.
type sshDialer func(string, string) (net.Conn, error)

// newSSHTunnel creates a SSH tunnel to a given address.
func newSSHTunnel(username, addr string, key ssh.Signer) (sshDialer, error) {
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dial ssh conn to %q: %v", addr, err)
	}
	return func(net, addr string) (net.Conn, error) {
		parts := strings.Split(addr, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("no port to connect to %q: %v", addr, parts)
		}
		log.Printf("tunnel: tunneling connection to: %q", addr)
		conn, err := conn.Dial("tcp", addr)
		if err != nil {
			log.Printf("tunnel: failed to connect to %q: %v", addr, err)
		}
		return conn, err
	}, nil
}

func parseSSHConnectionString(conn string) (username, addr string, err error) {
	parts := strings.Split(conn, "@")
	if len(parts) == 1 {
		usr, err := user.Current()
		if err != nil {
			return "", "", fmt.Errorf("failed to get current user: %v", err)
		}
		username = usr.Username
		addr = parts[0]
	} else {
		username = parts[0]
		addr = parts[1]
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", "", err
	}
	return
}

func SSHTunnel() libswarm.Sender {
	backend := libswarm.NewServer()
	backend.OnSpawn(func(cmd ...string) (libswarm.Sender, error) {
		if len(cmd) != 2 {
			return nil, fmt.Errorf("tunnel: spawn takes exactly 2 arguments, got %d; usage: %s", len(cmd), usage)
		}

		connStr, identityPath := cmd[0], cmd[1]
		username, addr, err := parseSSHConnectionString(connStr)
		if err != nil {
			return nil, fmt.Errorf("tunnel: invalid ssh connection string %q: %v", addr, err)
		}
		key, err := newSSHKey(identityPath)
		if err != nil {
			return nil, fmt.Errorf("tunnel: failed to get ssh key for identity %q: %v", identityPath, err)
		}
		log.Printf("tunnel: connecting to %q", addr)
		dialer, err := newSSHTunnel(username, addr, key)
		if err != nil {
			return nil, fmt.Errorf("tunnel: failed to create ssh tunnel to %q: %v", addr, err)
		}

		log.Printf("tunnel: connected to %q", addr)
		client := newClient()
		client.urlHost = dockerHost
		client.transport.Dial = dialer
		b := &dockerClientBackend{
			client: client,
			Server: libswarm.NewServer(),
		}
		b.Server.OnAttach(b.attach)
		b.Server.OnStart(b.start)
		b.Server.OnLs(b.ls)
		b.Server.OnSpawn(b.spawn)
		return b.Server, nil
	})
	return backend
}
