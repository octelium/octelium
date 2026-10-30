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

package suite

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
)

func TestServiceDNSAnswerErr(t *testing.T) {
	svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "test.default"}}
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}, Answer: []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "test.default.local.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			A: net.ParseIP("100.64.0.155")},
	}}
	assert.ErrorContains(t, serviceDNSAnswerErr(svc, "test.default.local", dns.TypeA, msg), "no A address yet")

	svc.Status = &corev1.Service_Status{Addresses: []*corev1.Service_Status_Address{
		{DualStackIP: &metav1.DualStackIP{Ipv4: "100.64.0.154", Ipv6: "fdee::154"}},
	}}
	assert.ErrorContains(t, serviceDNSAnswerErr(svc, "test.default.local", dns.TypeA, msg), "want one of [100.64.0.154]")

	svc.Status.Addresses[0].DualStackIP.Ipv4 = "100.64.0.155"
	assert.Nil(t, serviceDNSAnswerErr(svc, "test.default.local", dns.TypeA, msg))
	assert.Equal(t, []string{"fdee::154"}, serviceAddrs(svc, dns.TypeAAAA))

	msg.Authoritative = false
	assert.ErrorContains(t, serviceDNSAnswerErr(svc, "test.default.local", dns.TypeA, msg), "not answered authoritatively")
	msg.Authoritative = true
	msg.Rcode = dns.RcodeNameError
	assert.ErrorContains(t, serviceDNSAnswerErr(svc, "test.default.local", dns.TypeA, msg), "NXDOMAIN")
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = nil
	assert.ErrorContains(t, serviceDNSAnswerErr(svc, "test.default.local", dns.TypeA, msg), "no address records")
}
