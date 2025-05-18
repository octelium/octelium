// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows
// +build !windows


package essh

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"

	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type dctx struct {
	id string

	conn    net.Conn
	sshConn *ssh.ServerConn

	mu sync.Mutex

	isClosed bool

	usr      *user.User
	sameUser bool
}

type envVar struct {
	key string
	val string
}

func newDctx(conn net.Conn, sshConn *ssh.ServerConn, usr *user.User, sameUser bool) (*dctx, error) {
	ret := &dctx{
		id:       utilrand.GetRandomStringCanonical(4),
		conn:     conn,
		sshConn:  sshConn,
		usr:      usr,
		sameUser: sameUser,
	}

	zap.S().Debugf("new dctx %s created", ret.id)

	return ret, nil
}

func (c *dctx) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		zap.L().Debug("dctx is already closed. Nothing to be done...", zap.String("id", c.id))
		return nil
	}
	c.isClosed = true

	zap.S().Debugf("Closing dctx: %s", c.id)

	if c.sshConn != nil {
		c.sshConn.Close()
	}

	if c.conn != nil {
		c.conn.Close()
	}

	zap.S().Debugf("dctx is now closed: %s", c.id)

	return nil
}

func (c *dctx) getEnv(additional []*envVar) []string {
	editor := func() string {
		if _, err := exec.LookPath("vim"); err == nil {
			return "vim"
		}
		return "nano"
	}()

	curEnv := os.Environ()

	env := []string{}

	for _, keyVal := range curEnv {

		switch {
		case strings.HasPrefix(keyVal, "OCTELIUM_DOMAIN"):
			env = append(env, keyVal)
		}
	}

	setEnv(&env, "USERNAME", c.usr.Username)
	setEnv(&env, "TERM", "xterm-256color")
	setEnv(&env, "COLORTERM", "truecolor")
	setEnv(&env, "HOME", c.usr.HomeDir)
	setEnv(&env, "LANG", "en_US.utf8")
	// setEnv(&env, "LANGUAGE", "en_US:en")
	// setEnv(&env, "LC_ALL", "en_US.utf8")
	setEnv(&env, "EDITOR", editor)
	setEnv(&env, "VISUAL", editor)
	setEnv(&env, "USER", c.usr.Username)
	setEnv(&env, "LOGNAME", c.usr.Username)

	if val := os.Getenv("PATH"); val != "" {
		setEnv(&env, "PATH", val)
	} else {
		setEnv(&env, "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}

	for _, e := range additional {
		setEnv(&env, e.key, e.val)
	}

	return env
}

func setEnvExistingKey(envVars []string, key, val string) bool {
	for idx, envVar := range envVars {
		strs := strings.SplitAfterN(envVar, "=", 2)

		if len(strs) < 1 {
			continue
		}

		if strings.TrimSuffix(strs[0], "=") == key {
			envVars[idx] = fmt.Sprintf("%s=%s", key, val)
			return true
		}
	}
	return false
}

func setEnv(envVars *[]string, key, val string) {
	if !setEnvExistingKey(*envVars, key, val) {
		*envVars = append(*envVars, fmt.Sprintf("%s=%s", key, val))
	}
}
