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

package harness

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	connInfoConfigName = "sys:conn-info"
	resourcesTable     = "octelium_resources"
	wgDevice           = "octelium-wg"
)

func (h *H) ClusterDB(ctx context.Context) (*sql.DB, error) {
	h.dbMu.Lock()
	defer h.dbMu.Unlock()

	if h.clusterDB != nil {
		return h.clusterDB, nil
	}

	pg := h.Scenario.Storage.Postgres

	name, ns, ok := strings.Cut(pg.Host, ".")
	if !ok {
		return nil, errors.Errorf("Unexpected Postgres host %q", pg.Host)
	}
	ns, _, _ = strings.Cut(ns, ".")

	svc, err := h.k8sC.CoreV1().Services(ns).Get(ctx, name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, errors.Errorf("Could not find the Postgres Service %s/%s: %+v", ns, name, err)
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable&connect_timeout=10",
		pg.Username, h.State.PostgresPassword,
		net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(pg.Port))), pg.Database)

	db, err := ConnectSQL("postgres", dsn, SQLConnectBudget)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(4)
	db.SetConnMaxLifetime(10 * time.Minute)

	h.clusterDB = db
	return db, nil
}

type ConnInventory struct {
	At       time.Time
	Sessions []*corev1.Session
	ConnInfo *cclusterv1.ClusterConnInfo
	Network  *corev1.ClusterConfig_Status_Network
}

func (inv *ConnInventory) Connected() []*corev1.Session {
	var ret []*corev1.Session
	for _, sess := range inv.Sessions {
		if sess.Status != nil && sess.Status.Connection != nil {
			ret = append(ret, sess)
		}
	}
	return ret
}

func (inv *ConnInventory) ByUID() map[string]*corev1.Session {
	ret := make(map[string]*corev1.Session, len(inv.Sessions))
	for _, sess := range inv.Sessions {
		ret[sess.Metadata.Uid] = sess
	}
	return ret
}

func (h *H) ConnInventory(ctx context.Context) (*ConnInventory, error) {
	db, err := h.ClusterDB(ctx)
	if err != nil {
		return nil, err
	}

	cc, err := h.coreC.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
	if err != nil {
		return nil, err
	}

	ret := &ConnInventory{
		At:      time.Now(),
		Network: cc.GetStatus().GetNetwork(),
	}

	rows, err := db.QueryContext(ctx,
		fmt.Sprintf(`SELECT resource FROM %s WHERE api = $1 AND kind = $2`, resourcesTable),
		ucorev1.API, ucorev1.KindSession)
	if err != nil {
		return nil, errors.Errorf("Could not list the Sessions: %+v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}

		sess := &corev1.Session{}
		if err := pbutils.UnmarshalJSON(raw, sess); err != nil {
			return nil, errors.Errorf("Could not parse a Session: %+v", err)
		}

		if sess.Status != nil && sess.Status.Type == corev1.Session_Status_CLIENT {
			ret.Sessions = append(ret.Sessions, sess)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var raw []byte
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT resource FROM %s WHERE api = $1 AND kind = $2 AND resource->'metadata'->>'name' = $3`,
			resourcesTable),
		ucorev1.API, ucorev1.KindConfig, connInfoConfigName).Scan(&raw); err != nil {
		return nil, errors.Errorf("Could not read %s: %+v", connInfoConfigName, err)
	}

	cfg := &corev1.Config{}
	if err := pbutils.UnmarshalJSON(raw, cfg); err != nil {
		return nil, err
	}

	ret.ConnInfo = &cclusterv1.ClusterConnInfo{}
	if attrs := cfg.GetData().GetAttrs(); attrs != nil {
		if err := pbutils.StructToMessage(attrs, ret.ConnInfo); err != nil {
			return nil, errors.Errorf("Could not parse %s: %+v", connInfoConfigName, err)
		}
	}

	return ret, nil
}

type AddressReport struct {
	Sessions  int `json:"sessions"`
	Connected int `json:"connected"`
	WireGuard int `json:"wireguard"`
	QUIC      int `json:"quic"`
	V4Only    int `json:"v4Only"`
	V6Only    int `json:"v6Only"`
	DualStack int `json:"dualStack"`

	ActiveWG   int `json:"activeIndexesWG"`
	ActiveQUIC int `json:"activeIndexesQUIC"`

	LeakedWG       []uint32 `json:"leakedWG,omitempty"`
	LeakedQUIC     []uint32 `json:"leakedQUIC,omitempty"`
	UnreservedWG   []uint32 `json:"unreservedWG,omitempty"`
	UnreservedQUIC []uint32 `json:"unreservedQUIC,omitempty"`
	DuplicateIdx   []uint32 `json:"duplicateIndexes,omitempty"`

	DuplicateAddrs []string `json:"duplicateAddresses,omitempty"`
	OutOfSubnet    []string `json:"outOfSubnet,omitempty"`
	InvalidIndex   []string `json:"invalidIndex,omitempty"`
	Inconsistent   []string `json:"inconsistent,omitempty"`
}

func (r *AddressReport) Violations() []string {
	var ret []string

	add := func(what string, n int, sample any) {
		if n > 0 {
			ret = append(ret, fmt.Sprintf("%d %s, e.g. %v", n, what, sample))
		}
	}

	add("WireGuard address indexes are reserved without a connected Session (leaked)",
		len(r.LeakedWG), firstN(r.LeakedWG, 10))
	add("QUICv0 address indexes are reserved without a connected Session (leaked)",
		len(r.LeakedQUIC), firstN(r.LeakedQUIC, 10))
	add("WireGuard Connections use an address index that is not reserved",
		len(r.UnreservedWG), firstN(r.UnreservedWG, 10))
	add("QUICv0 Connections use an address index that is not reserved",
		len(r.UnreservedQUIC), firstN(r.UnreservedQUIC, 10))
	add("address indexes are reserved more than once",
		len(r.DuplicateIdx), firstN(r.DuplicateIdx, 10))
	add("addresses are assigned to more than one connected Session",
		len(r.DuplicateAddrs), firstN(r.DuplicateAddrs, 5))
	add("addresses are outside of their Connection subnet",
		len(r.OutOfSubnet), firstN(r.OutOfSubnet, 5))
	add("addresses use an invalid index", len(r.InvalidIndex), firstN(r.InvalidIndex, 5))
	add("Sessions have an inconsistent Connection state",
		len(r.Inconsistent), firstN(r.Inconsistent, 5))

	return ret
}

func (r *AddressReport) Err() error {
	if v := r.Violations(); len(v) > 0 {
		return errors.Errorf("The Connection address invariants are violated:\n  - %s",
			strings.Join(v, "\n  - "))
	}
	return nil
}

func (r *AddressReport) String() string {
	return fmt.Sprintf(
		"%d CLIENT Sessions, %d connected (wg=%d quic=%d v4=%d v6=%d both=%d), reserved wg=%d quic=%d",
		r.Sessions, r.Connected, r.WireGuard, r.QUIC, r.V4Only, r.V6Only, r.DualStack,
		r.ActiveWG, r.ActiveQUIC)
}

func firstN[T any](vals []T, n int) []T {
	if len(vals) <= n {
		return vals
	}
	return vals[:n]
}

func addrIndex(addr netip.Addr) uint32 {
	b := addr.AsSlice()
	return uint32(b[len(b)-2])<<8 | uint32(b[len(b)-1])
}

func connSubnet(network *corev1.ClusterConfig_Status_Network,
	typ corev1.Session_Status_Connection_Type) (v4, v6 netip.Prefix) {
	if network == nil {
		return
	}

	subnet := network.WgConnSubnet
	if typ == corev1.Session_Status_Connection_QUICV0 {
		subnet = network.QuicConnSubnet
	}
	if subnet == nil {
		return
	}

	v4, _ = netip.ParsePrefix(subnet.V4)
	v6, _ = netip.ParsePrefix(subnet.V6)
	return
}

func CheckConnAddresses(inv *ConnInventory) *AddressReport {
	ret := &AddressReport{Sessions: len(inv.Sessions)}

	reservedWG := map[uint32]int{}
	reservedQUIC := map[uint32]int{}
	if inv.ConnInfo != nil {
		for _, idx := range inv.ConnInfo.ActiveIndexesWG {
			reservedWG[idx]++
		}
		for _, idx := range inv.ConnInfo.ActiveIndexesQUIC {
			reservedQUIC[idx]++
		}
		ret.ActiveWG = len(inv.ConnInfo.ActiveIndexesWG)
		ret.ActiveQUIC = len(inv.ConnInfo.ActiveIndexesQUIC)
	}

	for _, m := range []map[uint32]int{reservedWG, reservedQUIC} {
		for idx, n := range m {
			if n > 1 {
				ret.DuplicateIdx = append(ret.DuplicateIdx, idx)
			}
		}
	}

	usedWG := map[uint32]bool{}
	usedQUIC := map[uint32]bool{}
	owners := map[netip.Addr]string{}
	dupes := map[string]bool{}

	for _, sess := range inv.Sessions {
		name := sess.Metadata.Name
		conn := sess.Status.Connection

		if sess.Status.IsConnected != (conn != nil) {
			ret.Inconsistent = append(ret.Inconsistent,
				fmt.Sprintf("%s: isConnected=%t but connection set=%t",
					name, sess.Status.IsConnected, conn != nil))
		}

		if conn == nil {
			continue
		}

		ret.Connected++

		used := usedWG
		switch conn.Type {
		case corev1.Session_Status_Connection_QUICV0:
			ret.QUIC++
			used = usedQUIC
		default:
			ret.WireGuard++
		}

		switch conn.L3Mode {
		case corev1.Session_Status_Connection_V4:
			ret.V4Only++
		case corev1.Session_Status_Connection_V6:
			ret.V6Only++
		default:
			ret.DualStack++
		}

		if len(conn.Addresses) == 0 {
			ret.Inconsistent = append(ret.Inconsistent, fmt.Sprintf("%s: connected without an address", name))
			continue
		}

		if len(conn.X25519PublicKey) != 32 {
			ret.Inconsistent = append(ret.Inconsistent, fmt.Sprintf("%s: no x25519 public key", name))
		}

		subnetV4, subnetV6 := connSubnet(inv.Network, conn.Type)

		for _, addr := range conn.Addresses {
			var idxs []uint32

			for _, item := range []struct {
				val    string
				subnet netip.Prefix
			}{
				{addr.V4, subnetV4},
				{addr.V6, subnetV6},
			} {
				if item.val == "" {
					continue
				}

				pfx, err := netip.ParsePrefix(item.val)
				if err != nil {
					ret.Inconsistent = append(ret.Inconsistent,
						fmt.Sprintf("%s: unparsable address %q", name, item.val))
					continue
				}

				ip := pfx.Addr()
				if owner, ok := owners[ip]; ok && owner != name {
					if !dupes[ip.String()] {
						dupes[ip.String()] = true
						ret.DuplicateAddrs = append(ret.DuplicateAddrs,
							fmt.Sprintf("%s (%s and %s)", ip, owner, name))
					}
				}
				owners[ip] = name

				if item.subnet.IsValid() && !item.subnet.Contains(ip) {
					ret.OutOfSubnet = append(ret.OutOfSubnet,
						fmt.Sprintf("%s: %s not in %s", name, ip, item.subnet))
				}

				idx := addrIndex(ip)
				if idx == 0 || idx%256 == 0 || idx >= 65535 {
					ret.InvalidIndex = append(ret.InvalidIndex, fmt.Sprintf("%s: %s", name, ip))
				}
				idxs = append(idxs, idx)
			}

			if len(idxs) == 2 && idxs[0] != idxs[1] {
				ret.Inconsistent = append(ret.Inconsistent,
					fmt.Sprintf("%s: the v4 and v6 addresses use different indexes", name))
			}
			if len(idxs) > 0 {
				used[idxs[0]] = true
			}
		}
	}

	diff := func(reserved map[uint32]int, used map[uint32]bool) (leaked, unreserved []uint32) {
		for idx := range reserved {
			if !used[idx] {
				leaked = append(leaked, idx)
			}
		}
		for idx := range used {
			if reserved[idx] == 0 {
				unreserved = append(unreserved, idx)
			}
		}
		slices.Sort(leaked)
		slices.Sort(unreserved)
		return
	}

	ret.LeakedWG, ret.UnreservedWG = diff(reservedWG, usedWG)
	ret.LeakedQUIC, ret.UnreservedQUIC = diff(reservedQUIC, usedQUIC)

	slices.Sort(ret.DuplicateIdx)
	sort.Strings(ret.DuplicateAddrs)

	return ret
}

func NewLeaks(before, after []uint32) []uint32 {
	prev := map[uint32]bool{}
	for _, idx := range before {
		prev[idx] = true
	}

	var ret []uint32
	for _, idx := range after {
		if !prev[idx] {
			ret = append(ret, idx)
		}
	}
	return ret
}

type WGPeer struct {
	PublicKey       string
	Endpoint        string
	AllowedIPs      []netip.Prefix
	LatestHandshake time.Time
	RxBytes         uint64
	TxBytes         uint64
}

func ParseWGDump(out string) ([]*WGPeer, error) {
	var ret []*WGPeer

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errors.Errorf("Empty WireGuard dump")
	}

	for i, line := range lines {
		fields := strings.Fields(line)
		if i == 0 {
			if len(fields) != 4 {
				return nil, errors.Errorf("Unexpected WireGuard interface line: %q", line)
			}
			continue
		}

		if len(fields) != 8 {
			return nil, errors.Errorf("Unexpected WireGuard peer line: %q", line)
		}

		peer := &WGPeer{PublicKey: fields[0], Endpoint: fields[2]}

		if fields[3] != "(none)" {
			for _, cidr := range strings.Split(fields[3], ",") {
				pfx, err := netip.ParsePrefix(cidr)
				if err != nil {
					return nil, errors.Errorf("Invalid allowed IP %q: %+v", cidr, err)
				}
				peer.AllowedIPs = append(peer.AllowedIPs, pfx)
			}
		}

		if sec, err := strconv.ParseInt(fields[4], 10, 64); err == nil && sec > 0 {
			peer.LatestHandshake = time.Unix(sec, 0)
		}
		peer.RxBytes, _ = strconv.ParseUint(fields[5], 10, 64)
		peer.TxBytes, _ = strconv.ParseUint(fields[6], 10, 64)

		ret = append(ret, peer)
	}

	return ret, nil
}

type PeerReport struct {
	Gateway  string   `json:"gateway"`
	Peers    int      `json:"peers"`
	Expected int      `json:"expected"`
	Missing  []string `json:"missing,omitempty"`
	Stale    []string `json:"stale,omitempty"`
	WrongIPs []string `json:"wrongAllowedIPs,omitempty"`
}

func (r *PeerReport) Err() error {
	var v []string
	if len(r.Missing) > 0 {
		v = append(v, fmt.Sprintf("%d connected WireGuard Sessions have no peer, e.g. %v",
			len(r.Missing), firstN(r.Missing, 5)))
	}
	if len(r.Stale) > 0 {
		v = append(v, fmt.Sprintf("%d peers belong to no connected WireGuard Session, e.g. %v",
			len(r.Stale), firstN(r.Stale, 5)))
	}
	if len(r.WrongIPs) > 0 {
		v = append(v, fmt.Sprintf("%d peers have the wrong allowed IPs, e.g. %v",
			len(r.WrongIPs), firstN(r.WrongIPs, 5)))
	}

	if len(v) == 0 {
		return nil
	}

	return errors.Errorf("The Gateway %s has %d WireGuard peers, want %d:\n  - %s",
		r.Gateway, r.Peers, r.Expected, strings.Join(v, "\n  - "))
}

func ExpectedAllowedIPs(sess *corev1.Session) []netip.Prefix {
	var ret []netip.Prefix

	s := ucorev1.ToSession(sess)
	for _, addr := range sess.Status.Connection.Addresses {
		if addr.V4 != "" && s.HasV4() {
			if pfx, err := netip.ParsePrefix(addr.V4); err == nil {
				ret = append(ret, pfx)
			}
		}
		if addr.V6 != "" && s.HasV6() {
			if pfx, err := netip.ParsePrefix(addr.V6); err == nil {
				ret = append(ret, pfx)
			}
		}
	}

	slices.SortFunc(ret, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return ret
}

func CheckGatewayPeers(gateway string, peers []*WGPeer, sessions []*corev1.Session) *PeerReport {
	ret := &PeerReport{Gateway: gateway, Peers: len(peers)}

	want := map[string]*corev1.Session{}
	for _, sess := range sessions {
		conn := sess.Status.Connection
		if conn == nil || conn.Type != corev1.Session_Status_Connection_WIREGUARD ||
			len(conn.X25519PublicKey) != 32 {
			continue
		}
		want[base64.StdEncoding.EncodeToString(conn.X25519PublicKey)] = sess
	}
	ret.Expected = len(want)

	got := map[string]*WGPeer{}
	for _, peer := range peers {
		got[peer.PublicKey] = peer
	}

	for key, sess := range want {
		peer, ok := got[key]
		if !ok {
			ret.Missing = append(ret.Missing, sess.Metadata.Name)
			continue
		}

		allowed := slices.Clone(peer.AllowedIPs)
		slices.SortFunc(allowed, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })

		if expected := ExpectedAllowedIPs(sess); !slices.Equal(allowed, expected) {
			ret.WrongIPs = append(ret.WrongIPs,
				fmt.Sprintf("%s: got %v want %v", sess.Metadata.Name, allowed, expected))
		}
	}

	for key := range got {
		if _, ok := want[key]; !ok {
			ret.Stale = append(ret.Stale, key)
		}
	}

	sort.Strings(ret.Missing)
	sort.Strings(ret.Stale)
	sort.Strings(ret.WrongIPs)

	return ret
}

func (h *H) NodeNetnsCmd(node, cmd string) string {
	if !scenario.IsAgentNode(node) {
		return fmt.Sprintf("sudo -n %s", cmd)
	}

	return fmt.Sprintf(
		`sudo -n nsenter --net=/proc/$(sudo -n docker inspect -f '{{.State.Pid}}' %s)/ns/net %s`,
		node, cmd)
}

func (h *H) GatewayWGPeers(ctx context.Context, gw *corev1.Gateway) ([]*WGPeer, error) {
	node := gw.GetStatus().GetNodeRef().GetName()
	if node == "" {
		return nil, errors.Errorf("The Gateway %s has no node", gw.Metadata.Name)
	}

	cmd := h.NodeNetnsCmd(node, fmt.Sprintf("wg show %s dump", wgDevice))

	out, err := h.Output(ctx, cmd)
	if err != nil {
		return nil, errors.Errorf("Could not dump the WireGuard device of the Gateway %s: %+v: %s",
			gw.Metadata.Name, err, bytes.TrimSpace(out))
	}

	return ParseWGDump(string(out))
}

func (h *H) CanInspectWireGuard(ctx context.Context) error {
	out, err := h.Output(ctx, "sudo -n wg --version")
	if err != nil {
		return errors.Errorf("wireguard-tools are not usable on this host: %+v: %s", err, out)
	}
	return nil
}

func (h *H) ListGateways(ctx context.Context) ([]*corev1.Gateway, error) {
	ret, err := h.coreC.ListGateway(ctx, &corev1.ListGatewayOptions{})
	if err != nil {
		return nil, err
	}
	return ret.Items, nil
}
