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
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const ingressDataplaneSvc = "octelium-ingress-dataplane"

func registerDevice(t *testing.T, sess *harness.AuthSession) *metav1.ObjectReference {
	t.Helper()

	begin, err := sess.C().RegisterDeviceBegin(sess.Ctx(t.Context()),
		&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				OsType:   authv1.RegisterDeviceBeginRequest_Info_LINUX,
				Hostname: utilrand.GetRandomStringCanonical(8),
				Id:       utilrand.GetRandomStringHex(64),
			},
		})
	require.Nil(t, err, "could not begin the Device registration")

	_, err = sess.C().RegisterDeviceFinish(sess.Ctx(t.Context()),
		&authv1.RegisterDeviceFinishRequest{Uid: begin.Uid})
	require.Nil(t, err, "could not finish the Device registration")

	ref := sess.Session(t).Status.DeviceRef
	require.NotNil(t, ref, "the Session was not bound to the registered Device")

	return ref
}

func userDevices(t *testing.T, h *harness.H, usr *corev1.User) []*corev1.Device {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), harness.DecisionBudget)
	defer cancel()

	itmList, err := h.CoreC().ListDevice(ctx, &corev1.ListDeviceOptions{
		UserRef: umetav1.GetObjectReference(usr),
	})
	if err != nil {
		t.Fatalf("Could not list the Devices of the User %s: %+v", usr.Metadata.Name, err)
	}

	return itmList.Items
}

func userAuthenticators(t *testing.T, h *harness.H, usr *corev1.User) []*corev1.Authenticator {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), harness.DecisionBudget)
	defer cancel()

	itmList, err := h.CoreC().ListAuthenticator(ctx, &corev1.ListAuthenticatorOptions{
		UserRef: umetav1.GetObjectReference(usr),
	})
	if err != nil {
		t.Fatalf("Could not list the Authenticators of the User %s: %+v",
			usr.Metadata.Name, err)
	}

	return itmList.Items
}

func testNocturneUserDeletion(t *testing.T, h *harness.H) {
	usr := h.CreateUser(t, &corev1.User{
		Spec: &corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
			Authorization: &corev1.User_Spec_Authorization{
				InlinePolicies: harness.InlineAllowAny("allow"),
			},
		},
	})

	first := h.NewAuthSession(t, harness.AuthSessionOpts{
		User:        usr,
		SessionType: corev1.Session_Status_CLIENT,
	})

	second := h.NewAuthSession(t, harness.AuthSessionOpts{
		User:        usr,
		SessionType: corev1.Session_Status_CLIENTLESS,
	})

	devRef := registerDevice(t, first)
	authn, _ := registerTOTPAuthenticator(t, first, "e2e gc")

	require.Equal(t, 2, len(h.UserSessions(t, usr)),
		"the User should own both of its Sessions before it is deleted")
	require.Equal(t, 1, len(userDevices(t, h, usr)))
	require.Equal(t, 1, len(userAuthenticators(t, h, usr)))

	_, err := h.CoreC().DeleteUser(t.Context(), &metav1.DeleteOptions{Uid: usr.Metadata.Uid})
	require.Nil(t, err, "could not delete the User")

	gone := map[string]func(ctx context.Context) error{
		fmt.Sprintf("the Session %s", first.Name()): func(ctx context.Context) error {
			_, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: first.Name()})
			return err
		},
		fmt.Sprintf("the Session %s", second.Name()): func(ctx context.Context) error {
			_, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: second.Name()})
			return err
		},
		fmt.Sprintf("the Device %s", devRef.Name): func(ctx context.Context) error {
			_, err := h.CoreC().GetDevice(ctx, &metav1.GetOptions{Uid: devRef.Uid})
			return err
		},
		fmt.Sprintf("the Authenticator %s", authn.Metadata.Name): func(ctx context.Context) error {
			_, err := h.CoreC().GetAuthenticator(ctx,
				&metav1.GetOptions{Uid: authn.Metadata.Uid})
			return err
		},
	}

	collected := h.Within(t, "the identity resources of the deleted User to be collected",
		harness.DecisionBudget, func(ctx context.Context) error {
			for what, get := range gone {
				err := get(ctx)
				if err == nil {
					return errors.Errorf("%s of the deleted User still exists", what)
				}
				if !grpcerr.IsNotFound(err) {
					return err
				}
			}
			return nil
		})

	zap.L().Info("User identity garbage collection", zap.Duration("elapsed", collected))
}

func testNocturneDeviceDeletion(t *testing.T, h *harness.H) {
	bound := h.NewAuthSession(t, harness.AuthSessionOpts{
		SessionType: corev1.Session_Status_CLIENT,
	})

	unbound := h.NewAuthSession(t, harness.AuthSessionOpts{
		User:        bound.User,
		SessionType: corev1.Session_Status_CLIENTLESS,
	})

	devRef := registerDevice(t, bound)

	boundName := bound.Name()
	unboundName := unbound.Name()
	require.NotEqual(t, boundName, unboundName)

	_, err := h.CoreC().DeleteDevice(t.Context(), &metav1.DeleteOptions{Uid: devRef.Uid})
	require.Nil(t, err, "could not delete the Device")

	collected := h.Within(t, "the Sessions of the deleted Device to be collected",
		harness.DecisionBudget, func(ctx context.Context) error {
			_, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: boundName})
			if err == nil {
				return errors.Errorf("the Session of the deleted Device still exists")
			}
			if !grpcerr.IsNotFound(err) {
				return err
			}
			return nil
		})

	zap.L().Info("Device Session garbage collection", zap.Duration("elapsed", collected))

	_, err = h.CoreC().GetSession(t.Context(), &metav1.GetOptions{Name: unboundName})
	assert.Nil(t, err,
		"deleting a Device must not affect the Sessions that are not bound to it")
}

func testNocturnePodAddresses(t *testing.T, h *harness.H) {
	svc := newManagedService(t, h, "nginx", 80)

	h.MustWaitService(t, svc.Metadata.Name)

	before := waitServiceAddresses(t, h, svc.Metadata.Name, 1)
	replaced := h.RestartService(t, svc.Metadata.Name)

	reconciled := h.Within(t, "the Service addresses to follow the replacement Pod",
		harness.DeploymentBudget, func(ctx context.Context) error {
			cur, err := h.CoreC().GetService(ctx,
				&metav1.GetOptions{Name: svc.Metadata.Name})
			if err != nil {
				return err
			}
			if len(cur.Status.Addresses) != 1 {
				return errors.Errorf("the Service reports %d addresses, want 1",
					len(cur.Status.Addresses))
			}
			if cur.Status.Addresses[0].PodRef.Uid == before[0].PodRef.Uid {
				return errors.Errorf("the Service still points at the replaced Pod %s",
					before[0].PodRef.Name)
			}
			return nil
		})

	zap.L().Info("Service address reconciliation",
		zap.Duration("replacement", replaced), zap.Duration("reconciled", reconciled))

	after := waitServiceAddresses(t, h, svc.Metadata.Name, 1)
	assert.NotEqual(t, before[0].PodRef.Uid, after[0].PodRef.Uid)

	pods, err := h.ServicePods(t.Context(), svc.Metadata.Name)
	require.Nil(t, err)

	live := map[string]struct{}{}
	for _, pod := range pods {
		live[string(pod.UID)] = struct{}{}
	}

	for _, addr := range after {
		_, ok := live[addr.PodRef.Uid]
		assert.True(t, ok,
			"the Service reports the address of the Pod %s which no longer exists",
			addr.PodRef.Name)
	}
}

func testNocturneRegionIngress(t *testing.T, h *harness.H) {
	svc, err := h.K8sC().CoreV1().Services(vutils.K8sNS).
		Get(t.Context(), ingressDataplaneSvc, k8smetav1.GetOptions{})
	require.Nil(t, err)

	want := k8sServiceIPs(svc)
	if len(want) == 0 {
		t.Skipf("the %s Kubernetes Service exposes no addresses on this scenario",
			ingressDataplaneSvc)
	}

	h.Eventually(t, fmt.Sprintf("the Region to publish the addresses of %s",
		ingressDataplaneSvc), harness.DecisionBudget, func(ctx context.Context) error {
		rgn, err := h.CoreC().GetRegion(ctx, &metav1.GetOptions{Name: "default"})
		if err != nil {
			return err
		}
		if rgn.Status == nil {
			return errors.Errorf("the Region has no status")
		}
		if !slices.Equal(rgn.Status.IngressAddresses, want) {
			return errors.Errorf("the Region publishes %v, want %v",
				rgn.Status.IngressAddresses, want)
		}
		return nil
	})
}

func k8sServiceIPs(svc *k8scorev1.Service) []string {
	if svc.Spec.ExternalIPs != nil {
		return svc.Spec.ExternalIPs
	}

	var ret []string
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		ret = append(ret, ing.IP)
	}

	return ret
}
