/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package admin

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
)

const (
	maxMCPProtocolVersions = 16
	maxMCPAllowedOrigins   = 64
	maxMCPEndpointPathLen  = 256

	maxMCPRequestBytesLimit     = 16 * 1024 * 1024
	maxMCPJSONDepthLimit        = 512
	maxMCPStreamEventBytesLimit = 4 * 1024 * 1024
)

func (s *Server) validateMCPConfig(ctx context.Context, cfg *corev1.Service_Spec_Config) error {
	mcp := cfg.GetMcp()
	if mcp == nil {
		return grpcutils.InvalidArg("MCP config is not set")
	}

	if err := s.validateMCPEndpoint(mcp.GetEndpoint()); err != nil {
		return err
	}

	if err := s.validateMCPProtocol(mcp.GetProtocol()); err != nil {
		return err
	}

	if err := s.validateMCPOrigin(mcp.GetOrigin()); err != nil {
		return err
	}

	if err := s.validateMCPLimits(mcp.GetLimits()); err != nil {
		return err
	}

	if err := s.validateHTTPHeader(ctx, mcp.GetHeader()); err != nil {
		return err
	}

	if err := s.validateHTTPAuth(ctx, mcp.GetAuth()); err != nil {
		return err
	}

	if err := s.validateHTTPPath(mcp.GetPath()); err != nil {
		return err
	}

	if err := s.validateHTTPPlugins(ctx, cfg.Name, mcp.GetPlugins()); err != nil {
		return err
	}

	if err := s.validateHTTPVisibility(mcp.GetVisibility()); err != nil {
		return err
	}

	for _, plugin := range mcp.GetPlugins() {
		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_:
			return grpcutils.InvalidArg(
				"The Cache plugin is unsupported for MCP Services: %s", plugin.Name)
		}
	}

	return nil
}

func (s *Server) validateMCPEndpoint(endpoint *corev1.Service_Spec_Config_MCP_Endpoint) error {
	if endpoint == nil || endpoint.Path == "" {
		return nil
	}

	path := endpoint.Path

	if len(path) > maxMCPEndpointPathLen {
		return grpcutils.InvalidArg("The MCP endpoint path is too long")
	}

	if !strings.HasPrefix(path, "/") {
		return grpcutils.InvalidArg("The MCP endpoint path must be absolute")
	}

	if strings.ContainsAny(path, "?#") {
		return grpcutils.InvalidArg(
			"The MCP endpoint path must not contain a query or a fragment")
	}

	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return grpcutils.InvalidArg(
				"The MCP endpoint path contains an invalid control character")
		}
	}

	if strings.Contains(path, "//") || strings.Contains(path, "/./") ||
		strings.Contains(path, "/../") || strings.HasSuffix(path, "/.") ||
		strings.HasSuffix(path, "/..") {
		return grpcutils.InvalidArg("The MCP endpoint path must be canonical")
	}

	if strings.HasPrefix(path, "/.well-known/") {
		return grpcutils.InvalidArg(
			"The MCP endpoint path must not be a reserved well-known path")
	}

	return nil
}

func (s *Server) validateMCPProtocol(protocol *corev1.Service_Spec_Config_MCP_Protocol) error {
	if protocol == nil {
		return nil
	}

	if len(protocol.Versions) > maxMCPProtocolVersions {
		return grpcutils.InvalidArg("Too many MCP protocol versions")
	}

	var seen []string
	for _, version := range protocol.Versions {
		if version == "" {
			return grpcutils.InvalidArg("An MCP protocol version cannot be empty")
		}
		if err := s.validateGenStr(version, true, "protocolVersion"); err != nil {
			return err
		}
		if slices.Contains(seen, version) {
			return grpcutils.InvalidArg("Duplicate MCP protocol version: %s", version)
		}
		seen = append(seen, version)
	}

	return nil
}

func (s *Server) validateMCPOrigin(origin *corev1.Service_Spec_Config_MCP_Origin) error {
	if origin == nil {
		return nil
	}

	if len(origin.Allowed) > maxMCPAllowedOrigins {
		return grpcutils.InvalidArg("Too many allowed MCP Origins")
	}

	for _, arg := range origin.Allowed {
		u, err := url.Parse(arg)
		if err != nil {
			return grpcutils.InvalidArg("Invalid MCP Origin: %s", arg)
		}

		switch u.Scheme {
		case "http", "https":
		default:
			return grpcutils.InvalidArg(
				"An MCP Origin must use the http or https scheme: %s", arg)
		}

		if u.Host == "" {
			return grpcutils.InvalidArg("An MCP Origin must have a host: %s", arg)
		}

		if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return grpcutils.InvalidArg(
				"An MCP Origin must only contain a scheme, a host and an optional port: %s", arg)
		}
	}

	return nil
}

func (s *Server) validateMCPLimits(limits *corev1.Service_Spec_Config_MCP_Limits) error {
	if limits == nil {
		return nil
	}

	if limits.MaxRequestBytes > maxMCPRequestBytesLimit {
		return grpcutils.InvalidArg("maxRequestBytes is above the maximum allowed value")
	}

	if limits.MaxJSONDepth > maxMCPJSONDepthLimit {
		return grpcutils.InvalidArg("maxJSONDepth is above the maximum allowed value")
	}

	if limits.MaxStreamEventBytes > maxMCPStreamEventBytesLimit {
		return grpcutils.InvalidArg("maxStreamEventBytes is above the maximum allowed value")
	}

	return nil
}
