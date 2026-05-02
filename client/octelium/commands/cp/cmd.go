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

package cp

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type args struct {
	Recursive bool
}

var cmdArgs args

func init() {
	Cmd.Flags().BoolVarP(&cmdArgs.Recursive, "recursive", "r", false, "Recursively copy directories")
}

var Cmd = &cobra.Command{
	Use:   "cp <source> <destination>",
	Short: "Copy files between the local filesystem and remote filesystems of connected Octelium sessions, or between two sessions",
	Long: `Copy files or directories between the local filesystem and remote filesystems of connected Octelium sessions,
or between two sessions.

Session paths are specified as <session-name>:<path>.
You can list Session names via the "octeliumctl get sess" command.
Local paths are specified as plain filesystem paths.

Use -r to copy directories recursively.`,
	Example: `
  # Copy a local file to a session
  octelium cp ./config.json john-123456:/home/user/config.json

  # Copy a file from a session to local
  octelium cp john-123456:/home/user/output.csv ./output.csv

  # Copy a local directory to a session
  octelium cp -r ./src/ john-123456:/home/user/src/

  # Copy a directory from a session to local
  octelium cp -r john-123456:/home/user/dist/ ./dist/

  # Copy a file from one session to another
  octelium cp john-123456:/home/user/data.json linus-abcdef:/home/user/data.json

  # Copy a directory from one session to another
  octelium cp -r john-123456:/home/user/data/ linus-abcdef:/home/user/data/`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
	Args: cobra.ExactArgs(2),
}

type Endpoint struct {
	User            string
	Path            string
	IsLocal         bool
	Addr            string
	HostKeyCallback ssh.HostKeyCallback

	Network string
}

func parseEndpoint(arg string) (*Endpoint, error) {
	idx := strings.Index(arg, ":")
	if idx > 0 {
		session := arg[:idx]
		path := arg[idx+1:]
		if session == "" {
			return nil, errors.Errorf("Invalid endpoint %q: session name is empty", arg)
		}
		if path == "" {
			return nil, errors.Errorf("Invalid endpoint %q: path is empty", arg)
		}
		return &Endpoint{
			User:    session,
			Path:    path,
			IsLocal: false,
		}, nil
	}
	return &Endpoint{
		Path:    arg,
		IsLocal: true,
	}, nil
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()

	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}
	src, err := parseEndpoint(args[0])
	if err != nil {
		return err
	}
	dst, err := parseEndpoint(args[1])
	if err != nil {
		return err
	}

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := userv1.NewMainServiceClient(conn)

	resp, err := c.GetStatus(ctx, &userv1.GetStatusRequest{})
	if err != nil {
		return err
	}

	if !resp.Session.Status.IsConnected {
		return errors.Errorf(
			`You must be connected to the Cluster. Please use "octelium connect" before running this command.`)
	}

	cfg, err := c.SetServiceConfigs(ctx, &userv1.SetServiceConfigsRequest{
		Name: "essh.octelium",
	})
	if err != nil {
		return err
	}

	hostKeyCallback, err := func() (ssh.HostKeyCallback, error) {
		if len(cfg.Configs) < 1 ||
			cfg.Configs[0].GetSsh() == nil ||
			len(cfg.Configs[0].GetSsh().KnownHosts) == 0 {
			return nil, errors.Errorf("Could not get Service knownHosts")
		}

		f, err := os.CreateTemp("", "known_hosts_*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())

		if _, err := f.WriteString(strings.Join(cfg.Configs[0].GetSsh().KnownHosts, "\n")); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()

		return knownhosts.New(f.Name())
	}()
	if err != nil {
		return err
	}

	network := func() string {
		switch cfg.L3Mode {
		case userv1.SetServiceConfigsResponse_V6:
			return "tcp6"
		default:
			return "tcp"
		}
	}()

	src.HostKeyCallback = hostKeyCallback
	src.Addr = net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
	src.Network = network

	dst.HostKeyCallback = hostKeyCallback
	dst.Addr = net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
	dst.Network = network

	return DoCommand(ctx, &DoCommandOpts{
		Src:       src,
		Dst:       dst,
		Recursive: cmdArgs.Recursive,
	})
}

type DoCommandOpts struct {
	Recursive bool
	Src       *Endpoint
	Dst       *Endpoint
}

func DoCommand(ctx context.Context, o *DoCommandOpts) error {

	src := o.Src
	dst := o.Dst

	if src.IsLocal && dst.IsLocal {
		return errors.Errorf("At least one of source or destination must be a session path (session-name:/path)")
	}

	switch {
	case src.IsLocal && !dst.IsLocal:
		return copyLocalToSession(src, dst, o.Recursive)
	case !src.IsLocal && dst.IsLocal:
		return copySessionToLocal(src, dst.Path, o.Recursive)
	default:
		return copySessionToSession(src, dst, o.Recursive)
	}
}

func dialSFTP(e *Endpoint) (*sftp.Client, *ssh.Client, error) {

	sessionName := e.User
	sshCfg := &ssh.ClientConfig{
		User: sessionName,
		Auth: []ssh.AuthMethod{},

		HostKeyCallback: func() ssh.HostKeyCallback {
			if e.HostKeyCallback != nil {
				return e.HostKeyCallback
			}
			return ssh.InsecureIgnoreHostKey()
		}(),
	}

	addr := e.Addr

	zap.L().Debug("Dialing SSH", zap.String("addr", addr), zap.String("user", sessionName))

	sshClient, err := ssh.Dial(func() string {
		switch e.Network {
		case "tcp", "tcp6":
			return e.Network
		default:
			return "tcp"
		}
	}(), addr, sshCfg)
	if err != nil {
		return nil, nil, errors.Errorf("Could not connect to session %q at %s: %+v",
			sessionName, addr, err)
	}

	sftpClient, err := sftp.NewClient(sshClient, sftp.MaxPacket(1<<15))
	if err != nil {
		sshClient.Close()
		return nil, nil, errors.Errorf("Could not open SFTP session for %q: %+v", sessionName, err)
	}

	return sftpClient, sshClient, nil
}

func copyLocalToSession(src, dst *Endpoint, recursive bool) error {
	localPath := src.Path
	remotePath := dst.Path

	sftpC, sshC, err := dialSFTP(dst)
	if err != nil {
		return err
	}
	defer sshC.Close()
	defer sftpC.Close()

	info, err := os.Stat(localPath)
	if err != nil {
		return errors.Errorf("Could not stat %q: %+v", localPath, err)
	}

	if info.IsDir() {
		if !recursive {
			return errors.Errorf("%q is a directory; use -r to copy directories", localPath)
		}
		return uploadDir(sftpC, localPath, remotePath)
	}
	return uploadFile(sftpC, localPath, remotePath)
}

func uploadFile(sftpC *sftp.Client, localPath, remotePath string) error {
	src, err := os.Open(localPath)
	if err != nil {
		return errors.Errorf("Could not open %q: %+v", localPath, err)
	}
	defer src.Close()

	info, err := src.Stat()
	if err != nil {
		return err
	}

	if rInfo, err := sftpC.Stat(remotePath); err == nil && rInfo.IsDir() {
		remotePath = filepath.Join(remotePath, filepath.Base(localPath))
	}

	dst, err := sftpC.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return errors.Errorf("Could not create remote file %q: %+v", remotePath, err)
	}
	defer dst.Close()

	if err := dst.Chmod(info.Mode()); err != nil {
		return errors.Errorf("Could not chmod remote file %q: %+v", remotePath, err)
	}

	n, err := io.Copy(dst, src)
	if err != nil {
		return errors.Errorf("Could not upload %q after %d bytes: %+v", localPath, n, err)
	}

	cliutils.LineInfo("%s → %s (%d bytes)\n", localPath, remotePath, n)
	return nil
}

func uploadDir(sftpC *sftp.Client, localDir, remoteDir string) error {
	return filepath.Walk(localDir, func(localPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(localDir, localPath)
		if err != nil {
			return err
		}
		remotePath := filepath.Join(remoteDir, relPath)

		if info.IsDir() {
			return sftpC.MkdirAll(remotePath)
		}
		return uploadFile(sftpC, localPath, remotePath)
	})
}

func copySessionToLocal(src *Endpoint, localPath string, recursive bool) error {

	sessionName := src.User
	remotePath := src.Path

	sftpC, sshC, err := dialSFTP(src)
	if err != nil {
		return err
	}
	defer sshC.Close()
	defer sftpC.Close()

	rInfo, err := sftpC.Stat(remotePath)
	if err != nil {
		return errors.Errorf("Could not stat remote path %q on session %q: %+v",
			remotePath, sessionName, err)
	}

	if rInfo.IsDir() {
		if !recursive {
			return errors.Errorf("%q is a directory; use -r to copy directories", remotePath)
		}
		return downloadDir(sftpC, remotePath, localPath)
	}
	return downloadFile(sftpC, remotePath, localPath)
}

func downloadFile(sftpC *sftp.Client, remotePath, localPath string) error {
	rFile, err := sftpC.Open(remotePath)
	if err != nil {
		return errors.Errorf("Could not open remote file %q: %+v", remotePath, err)
	}
	defer rFile.Close()

	rInfo, err := rFile.Stat()
	if err != nil {
		return err
	}

	if lInfo, err := os.Stat(localPath); err == nil && lInfo.IsDir() {
		localPath = filepath.Join(localPath, filepath.Base(remotePath))
	}

	lFile, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, rInfo.Mode())
	if err != nil {
		return errors.Errorf("Could not create local file %q: %+v", localPath, err)
	}
	defer lFile.Close()

	n, err := io.Copy(lFile, rFile)
	if err != nil {
		return errors.Errorf("Could not download %q after %d bytes: %+v", remotePath, n, err)
	}

	cliutils.LineInfo("%s:%s → %s (%d bytes)\n", remotePath, remotePath, localPath, n)
	return nil
}

func downloadDir(sftpC *sftp.Client, remoteDirPath, localDirPath string) error {
	walker := sftpC.Walk(remoteDirPath)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		relPath, err := filepath.Rel(remoteDirPath, walker.Path())
		if err != nil {
			return err
		}
		localPath := filepath.Join(localDirPath, relPath)

		if walker.Stat().IsDir() {
			if err := os.MkdirAll(localPath, walker.Stat().Mode()); err != nil {
				return err
			}
			continue
		}
		if err := downloadFile(sftpC, walker.Path(), localPath); err != nil {
			return err
		}
	}
	return nil
}

func copySessionToSession(src, dst *Endpoint, recursive bool) error {

	srcSession := src.User
	dstSession := dst.User

	srcPath := src.Path
	dstPath := dst.Path

	srcSFTP, srcSSH, err := dialSFTP(src)
	if err != nil {
		return errors.Errorf("Could not connect to source session %q: %+v", srcSession, err)
	}
	defer srcSSH.Close()
	defer srcSFTP.Close()

	dstSFTP, dstSSH, err := dialSFTP(dst)
	if err != nil {
		return errors.Errorf("Could not connect to destination session %q: %+v", dstSession, err)
	}
	defer dstSSH.Close()
	defer dstSFTP.Close()

	rInfo, err := srcSFTP.Stat(srcPath)
	if err != nil {
		return errors.Errorf("Could not stat source path %q on session %q: %+v",
			srcPath, srcSession, err)
	}

	if rInfo.IsDir() {
		if !recursive {
			return errors.Errorf("%q is a directory; use -r to copy directories", srcPath)
		}
		return transferDir(srcSFTP, dstSFTP, srcPath, dstPath)
	}
	return transferFile(srcSFTP, dstSFTP, srcPath, dstPath)
}

func transferFile(srcSFTP, dstSFTP *sftp.Client, srcPath, dstPath string) error {
	srcFile, err := srcSFTP.Open(srcPath)
	if err != nil {
		return errors.Errorf("Could not open source file %q: %+v", srcPath, err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	if dInfo, err := dstSFTP.Stat(dstPath); err == nil && dInfo.IsDir() {
		dstPath = filepath.Join(dstPath, filepath.Base(srcPath))
	}

	dstFile, err := dstSFTP.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return errors.Errorf("Could not create destination file %q: %+v", dstPath, err)
	}
	defer dstFile.Close()

	if err := dstFile.Chmod(srcInfo.Mode()); err != nil {
		return errors.Errorf("Could not chmod destination file %q: %+v", dstPath, err)
	}

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return errors.Errorf("Could not transfer %q after %d bytes: %+v", srcPath, n, err)
	}

	cliutils.LineInfo("%s → %s (%d bytes)\n", srcPath, dstPath, n)
	return nil
}

func transferDir(srcSFTP, dstSFTP *sftp.Client, srcDir, dstDir string) error {
	walker := srcSFTP.Walk(srcDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		relPath, err := filepath.Rel(srcDir, walker.Path())
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dstDir, relPath)

		if walker.Stat().IsDir() {
			if err := dstSFTP.MkdirAll(dstPath); err != nil {
				return errors.Errorf("Could not create remote directory %q: %+v", dstPath, err)
			}
			continue
		}
		if err := transferFile(srcSFTP, dstSFTP, walker.Path(), dstPath); err != nil {
			return err
		}
	}
	return nil
}
