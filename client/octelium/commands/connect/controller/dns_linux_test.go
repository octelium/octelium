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

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetResolvctlArgs(t *testing.T) {
	dnsServers := []string{"100.64.0.53", "fd00::53"}
	searchDomains := []string{"local.example.com"}

	dnsArgs, domainArgs := getResolvctlArgs(true, "octelium0", dnsServers, searchDomains)
	assert.Equal(t, []string{"dns", "octelium0", "100.64.0.53", "fd00::53"}, dnsArgs)
	assert.Equal(t, []string{"domain", "octelium0", "local.example.com"}, domainArgs)

	dnsArgs, domainArgs = getResolvctlArgs(false, "octelium0", dnsServers, searchDomains)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-dns", "100.64.0.53",
		"--set-dns", "fd00::53",
	}, dnsArgs)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-domain", "local.example.com",
	}, domainArgs)
}

func TestGetResolvctlArgsWithMultipleSearchDomains(t *testing.T) {
	searchDomains := []string{"local.example.com", "svc.example.com"}

	_, domainArgs := getResolvctlArgs(true, "octelium0", []string{"100.64.0.53"}, searchDomains)
	assert.Equal(t,
		[]string{"domain", "octelium0", "local.example.com", "svc.example.com"}, domainArgs)

	_, domainArgs = getResolvctlArgs(false, "octelium0", []string{"100.64.0.53"}, searchDomains)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-domain", "local.example.com",
		"--set-domain", "svc.example.com",
	}, domainArgs)
}

func TestGetResolvctlDomains(t *testing.T) {
	c, _ := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	assert.Equal(t, []string{"local.example.com"}, c.getResolvctlDomains())

	c.c.Preferences.FullDNS = true
	assert.Equal(t, []string{"local.example.com", "~."}, c.getResolvctlDomains())
}

func TestGetResolvctlArgsInFullDNSMode(t *testing.T) {
	c, _ := newTestResolvConfCtl(t, []string{"100.64.0.53"})
	c.c.Preferences.FullDNS = true

	dnsArgs, domainArgs := getResolvctlArgs(true, "octelium0",
		[]string{"127.0.0.100"}, c.getResolvctlDomains())
	assert.Equal(t, []string{"dns", "octelium0", "127.0.0.100"}, dnsArgs)
	assert.Equal(t, []string{"domain", "octelium0", "local.example.com", "~."}, domainArgs)

	dnsArgs, domainArgs = getResolvctlArgs(false, "octelium0",
		[]string{"127.0.0.100"}, c.getResolvctlDomains())
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-dns", "127.0.0.100",
	}, dnsArgs)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-domain", "local.example.com",
		"--set-domain", "~.",
	}, domainArgs)
}

func TestGetResolvctlDefaultRouteArgs(t *testing.T) {
	assert.Equal(t, []string{"default-route", "octelium0", "yes"},
		getResolvctlDefaultRouteArgs("octelium0"))
}
