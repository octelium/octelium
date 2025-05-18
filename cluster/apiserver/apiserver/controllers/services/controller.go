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

package svccontroller

import (
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"go.uber.org/zap"
)

/*
func (c *Controller) handleAdd(ctx context.Context, svc *corev1.Service) error {

		svc, err := c.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		if err != nil {
			return errors.Errorf("Could not get Service: %+v", err)
		}

		conns, err := upstream.SetServiceUpstreams(ctx, c.octeliumC, svc)
		if err != nil {
			return errors.Errorf("Could not set service upstreams: %+v", err)
		}

		_, err = c.octeliumC.CoreC().UpdateService(ctx, svc)
		if err != nil {
			return errors.Errorf("Could not update service: %+v", err)
		}

		var updatedConns []*corev1.Session

		for _, conn := range conns {
			nConn, err := c.octeliumC.CoreC().UpdateSession(ctx, conn)
			if err != nil {
				return errors.Errorf("Could not update conn %s upstreams after svc %s add", conn.Metadata.Name, svc.Metadata.Name)
			}
			if nConn.Metadata.ResourceVersion != conn.Metadata.ResourceVersion {
				updatedConns = append(updatedConns, nConn)
			}

		}

		for _, conn := range updatedConns {

			zap.S().Debugf("Publishing add svc %s/%s to conn %s", svc.Status.NamespaceRef.Name, svc.Metadata.Name, conn.Metadata.Name)

			if err := c.ctlI.SendMessage(&userv1.ConnectResponse{
				Event: &userv1.ConnectResponse_AddService_{
					AddService: &userv1.ConnectResponse_AddService{
						Service: func() *userv1.HostedService {
							svcs := upstream.GetHostServicesFromConn(conn)
							for _, cur := range svcs {
								if cur.Name == svc.Metadata.Name {
									return cur
								}
							}
							zap.S().Errorf("Could not find hosted Service of %s/%s on Conn %s. This SHOULD NOT HAPPEN.",
								svc.Status.NamespaceRef.Name, svc.Metadata.Name, conn.Metadata.Name)
							return nil
						}(),
					},
				},
			}, conn.Metadata.Uid); err != nil {
				zap.S().Errorf("Could not publish conn message: %+v", err)
			}
		}

		return nil
	}

func (c *Controller) handleUpdate(ctx context.Context, svc *corev1.Service, oldSvc *corev1.Service) error {

		svc, err := c.octeliumC.CoreC().GetService(ctx,
			&rmetav1.GetOptions{Name: svc.Metadata.Name, StatusNamespaceName: svc.Status.NamespaceRef.Name})
		if err != nil {
			zap.S().Errorf("Could not get Service: %+v", err)
			return err
		}

		sessL, err := upstream.SetServiceUpstreams(ctx, c.octeliumC, svc)
		if err != nil {
			return err
		}

		var updatedSesss []*corev1.Session

		for _, sess := range sessL {
			nConn, err := c.octeliumC.CoreC().UpdateSession(ctx, sess)
			if err != nil {
				return errors.Errorf("Could not update Session %s upstreams after svc %s add", sess.Metadata.Name, svc.Metadata.Name)
			}
			if nConn.Metadata.ResourceVersion != sess.Metadata.ResourceVersion {
				updatedSesss = append(updatedSesss, nConn)
			}

		}

		_, err = c.octeliumC.CoreC().UpdateService(ctx, svc)
		if err != nil {
			zap.S().Errorf("Could not update service: %+v", err)
			return err
		}

		for _, conn := range updatedSesss {

			if err := c.ctlI.SendMessage(&userv1.ConnectResponse{
				Event: &userv1.ConnectResponse_UpdateService_{
					UpdateService: &userv1.ConnectResponse_UpdateService{
						Service: func() *userv1.HostedService {
							svcs := upstream.GetHostServicesFromConn(conn)
							for _, cur := range svcs {
								if cur.Name == svc.Metadata.Name {
									return cur
								}
							}

							zap.S().Errorf("Could not find hosted Service of %s/%s on Conn %s. This SHOULD NOT HAPPEN.",
								svc.Status.NamespaceRef.Name, svc.Metadata.Name, conn.Metadata.Name)
							return nil
						}(),
					},
				},
			}, conn.Metadata.Uid); err != nil {
				zap.S().Errorf("Could not publish conn message: %+v", err)
			}

		}

		return nil
	}

func (c *Controller) handleDelete(ctx context.Context, n *corev1.Service) error {

		hostConns, err := upstream.GetServiceHostConns(ctx, c.octeliumC, n)
		if err != nil {
			return err
		}

		for _, usrConn := range hostConns {

			if err := c.ctlI.SendMessage(&userv1.ConnectResponse{
				Event: &userv1.ConnectResponse_DeleteService_{
					DeleteService: &userv1.ConnectResponse_DeleteService{
						Name:      n.Metadata.Name,
						Namespace: n.Status.NamespaceRef.Name,
					},
				},
			}, usrConn.Metadata.Uid); err != nil {
				zap.S().Errorf("Could not publish conn message: %+v", err)
			}
		}

		return nil
	}
*/
func (c *Controller) setDNSState(dnsSvc *corev1.Service) error {

	zap.S().Debugf("Sending new DNS servers")
	dnsServers := []string{}
	if len(dnsSvc.Status.Addresses) == 0 {
		return nil
	}

	for _, addr := range dnsSvc.Status.Addresses {
		if addr.DualStackIP.Ipv4 != "" {
			dnsServers = append(dnsServers, addr.DualStackIP.Ipv4)
		}

		if addr.DualStackIP.Ipv6 != "" {
			dnsServers = append(dnsServers, addr.DualStackIP.Ipv6)
		}
	}

	return c.ctlI.BroadcastMessage(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_UpdateDNS_{
			UpdateDNS: &userv1.ConnectResponse_UpdateDNS{
				Dns: &userv1.DNS{
					Servers: dnsServers,
				},
			},
		},
	})
}
