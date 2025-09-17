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

package upstream

import (
	"context"
	"fmt"
	"net/url"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func setConnectionUpstreamsListener(ctx context.Context,
	octeliumC octeliumc.ClientInterface,
	sess *corev1.Session,
	svc *corev1.Service) error {

	conn := sess.Status.Connection
	if conn == nil {
		return errors.Errorf("Connection is not set in the Session")
	}

	// l := svc.Spec

	upstreamBackend := func() *url.URL {

		eps := ucorev1.ToService(svc).GetAllUpstreamEndpoints()

		for _, b := range eps {
			if b.User != "" {
				if userRef, err := ucorev1.ToService(svc).GetHostUserRef(b.User); err == nil &&
					userRef.Uid == sess.Status.UserRef.Uid {
					u, _ := url.Parse(b.Url)
					return u
				}
			}
			/*
				if b.User != "" && umetav1.ToMetadata(svc.Metadata).GetCoreUserUID(b.User) == sess.Status.UserRef.Uid {
					u, _ := url.Parse(b.Url)
					return u
				}
			*/
		}
		return nil
	}()

	if upstreamBackend == nil {
		return errors.Errorf("Cannot find listener backend for the User: %s", sess.Status.UserRef.Name)
	}

	port := int32(ucorev1.ToService(svc).UpstreamRealPort())

	upstreamListener := &corev1.Session_Status_Connection_Upstream{
		NamespaceRef: svc.Status.NamespaceRef,
		L4Type: func() corev1.Session_Status_Connection_Upstream_L4Type {
			if ucorev1.ToService(svc).L4Type() == corev1.Service_Spec_UDP {
				return corev1.Session_Status_Connection_Upstream_UDP
			} else {
				return corev1.Session_Status_Connection_Upstream_TCP
			}
		}(),
		ServiceRef: umetav1.GetObjectReference(svc),

		Backend: &corev1.Session_Status_Connection_Upstream_Backend{
			Host: upstreamBackend.Hostname(),
			Port: port,
		},

		Mode: func() corev1.Session_Status_Connection_Upstream_Mode {
			if ucorev1.ToService(svc).IsESSH() {
				return corev1.Session_Status_Connection_Upstream_ESSH
			}
			return corev1.Session_Status_Connection_Upstream_DEFAULT
		}(),
	}

	for _, upstream := range conn.Upstreams {
		if upstream.ServiceRef.Uid == svc.Metadata.Uid {
			zap.L().Debug("Upstream for Service already exists", zap.Any("svc", svc), zap.Any("sess", sess))
			upstream.Backend = &corev1.Session_Status_Connection_Upstream_Backend{
				Host: upstreamBackend.Hostname(),
				Port: port,
			}
			return nil
		}
	}

	zap.L().Debug("Adding upstream Service", zap.Any("svc", svc), zap.Any("sess", sess))

	lisPort, err := getListenerPort(sess)
	if err != nil {
		return err
	}

	upstreamListener.Port = int32(lisPort)
	conn.Upstreams = append(conn.Upstreams, upstreamListener)
	return nil
}

func AddAddressToConnection(ctx context.Context,
	octeliumC octeliumc.ClientInterface,
	sess *corev1.Session) error {

	conn := sess.Status.Connection
	if conn == nil {
		return errors.Errorf("Connection is not set in the Session")
	}

	switch conn.Type {
	case corev1.Session_Status_Connection_QUICV0, corev1.Session_Status_Connection_WIREGUARD:
	default:
		return errors.Errorf("Cannot adding addresses without knowing Connection type")
	}

	cfg, err := octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
	if err != nil {
		return err
	}
	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	var idx uint32

	networkInfo := &cclusterv1.ClusterConnInfo{}
	if err := pbutils.StructToMessage(cfg.Data.GetAttrs(), networkInfo); err != nil {
		return err
	}

	hasIndex := func(arg uint32) bool {
		switch conn.Type {
		case corev1.Session_Status_Connection_WIREGUARD:
			for _, itm := range networkInfo.ActiveIndexesWG {
				if itm == arg {
					return true
				}
			}
		case corev1.Session_Status_Connection_QUICV0:
			for _, itm := range networkInfo.ActiveIndexesQUIC {
				if itm == arg {
					return true
				}
			}
		}

		return false
	}

	for i := 0; i < 100000; i++ {
		curIdx, err := utilrand.GetRandomIPIndex()
		if err != nil {
			return err
		}
		if !hasIndex(uint32(curIdx)) {
			idx = curIdx
		}
	}

	if idx == 0 {
		return errors.Errorf("Could not find a valid IP")
	}

	switch conn.Type {
	case corev1.Session_Status_Connection_WIREGUARD:
		networkInfo.ActiveIndexesWG = append(networkInfo.ActiveIndexesWG, idx)
	case corev1.Session_Status_Connection_QUICV0:
		networkInfo.ActiveIndexesQUIC = append(networkInfo.ActiveIndexesQUIC, idx)
	}

	attrs, err := pbutils.MessageToStruct(networkInfo)
	if err != nil {
		return err
	}

	cfg.Data.Type = &corev1.Config_Data_Attrs{
		Attrs: attrs,
	}

	_, err = octeliumC.CoreC().UpdateConfig(ctx, cfg)
	if err != nil {
		return err
	}

	var connSubnet *metav1.DualStackNetwork

	switch conn.Type {
	case corev1.Session_Status_Connection_QUICV0:
		connSubnet = &metav1.DualStackNetwork{
			V4: cc.Status.Network.QuicConnSubnet.V4,
			V6: cc.Status.Network.QuicConnSubnet.V6,
		}
	case corev1.Session_Status_Connection_WIREGUARD:
		connSubnet = &metav1.DualStackNetwork{
			V4: cc.Status.Network.WgConnSubnet.V4,
			V6: cc.Status.Network.WgConnSubnet.V6,
		}
	}

	connIP, err := vutils.GetDualStackIPByIndex(connSubnet, int(idx))
	if err != nil {
		return err
	}

	conn.Addresses = append(conn.Addresses, &metav1.DualStackNetwork{
		V4: func() string {
			if connIP.Ipv4 != "" {
				return fmt.Sprintf("%s/32", connIP.Ipv4)
			} else {
				return ""
			}
		}(),
		V6: func() string {
			if connIP.Ipv6 != "" {
				return fmt.Sprintf("%s/128", connIP.Ipv6)
			} else {
				return ""
			}
		}(),
	})

	return nil
}

func removeAddressFromConnection(ctx context.Context, octeliumC octeliumc.ClientInterface,
	sess *corev1.Session, idx int) error {

	if sess.Status.Connection == nil || len(sess.Status.Connection.Addresses) == 0 {
		return nil
	}

	zap.L().Debug("Removing an address from Session",
		zap.Any("addr", sess.Status.Connection.Addresses[idx]), zap.Any("sess", sess))

	cfg, err := octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
	if err != nil {
		return err
	}

	networkInfo := &cclusterv1.ClusterConnInfo{}
	if err := pbutils.StructToMessage(cfg.Data.GetAttrs(), networkInfo); err != nil {
		return err
	}

	removeConnIndex(networkInfo,
		uint32(umetav1.ToDualStackIP(
			umetav1.ToDualStackNetwork(sess.Status.Connection.Addresses[idx]).ToIP()).GetIndex()),
		sess.Status.Connection.Type)

	attrs, err := pbutils.MessageToStruct(networkInfo)
	if err != nil {
		return err
	}

	cfg.Data.Type = &corev1.Config_Data_Attrs{
		Attrs: attrs,
	}

	_, err = octeliumC.CoreC().UpdateConfig(ctx, cfg)
	if err != nil {
		return err
	}

	return nil
}

func RemoveAllAddressFromConnection(ctx context.Context, octeliumC octeliumc.ClientInterface,
	sess *corev1.Session) error {
	if sess.Status.Connection == nil || len(sess.Status.Connection.Addresses) == 0 {
		return nil
	}

	zap.L().Debug("Removing all addresses from the Session",
		zap.String("sessName", sess.Metadata.Name), zap.Any("connection", sess.Status.Connection))

	for i := 0; i < len(sess.Status.Connection.Addresses); i++ {
		if err := removeAddressFromConnection(ctx, octeliumC, sess, i); err != nil {
			return err
		}
	}

	sess.Status.Connection.Addresses = nil

	return nil
}

func removeConnIndex(network *cclusterv1.ClusterConnInfo, arg uint32, typ corev1.Session_Status_Connection_Type) {

	switch typ {
	case corev1.Session_Status_Connection_WIREGUARD:
		for i, itm := range network.ActiveIndexesWG {
			if itm == arg {
				network.ActiveIndexesWG = append(network.ActiveIndexesWG[:i], network.ActiveIndexesWG[i+1:]...)
				return
			}
		}
	case corev1.Session_Status_Connection_QUICV0:
		for i, itm := range network.ActiveIndexesQUIC {
			if itm == arg {
				network.ActiveIndexesQUIC = append(network.ActiveIndexesQUIC[:i], network.ActiveIndexesQUIC[i+1:]...)
				return
			}
		}
	}
}

func getListenerPort(sess *corev1.Session) (int, error) {
	conn := sess.Status.Connection
	if conn == nil {
		return 0, errors.Errorf("Connection is not set in the Session")
	}

	curPorts := []int32{}

	for _, l := range sess.Status.Connection.Upstreams {
		curPorts = append(curPorts, l.Port)
	}

	isInList := func(arg int32) bool {
		for _, cur := range curPorts {
			if cur == arg {
				return true
			}
		}
		return false
	}

	if conn.ServiceOptions == nil {
		return 0, errors.Errorf("Nil ServiceOptions of Conn %s. THIS SHOULD NOT HAPPEN", sess.Metadata.Name)
	}

	for i := conn.ServiceOptions.PortStart; i < conn.ServiceOptions.PortStart+10000; i++ {
		if !isInList(i) {
			return int(i), nil
		}
	}

	return 0, errors.Errorf("Could not choose port for Session: %s", sess.Metadata.Name)
}
