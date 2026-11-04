package genesis

import (
	"context"
	"net/netip"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (g *Genesis) validateClusterNetwork(ctx context.Context, cc *corev1.ClusterConfig, bootstrap *cbootstrapv1.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var allocated []netip.Prefix
	values := []string{}
	if ucorev1.ToClusterConfig(cc).HasV4() {
		values = append(values, cc.Status.Network.GetClusterNetwork().GetV4())
	}
	if ucorev1.ToClusterConfig(cc).HasV6() {
		values = append(values, cc.Status.Network.GetClusterNetwork().GetV6())
	}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return errors.Wrap(err, "Invalid allocated Cluster network")
		}
		allocated = append(allocated, prefix)
	}
	for _, host := range []string{bootstrap.GetSpec().GetPrimaryStorage().GetPostgresql().GetHost(), bootstrap.GetSpec().GetSecondaryStorage().GetRedis().GetHost()} {
		if addr, err := netip.ParseAddr(host); err == nil {
			if err := checkNetworkOverlap(allocated, addr.Unmap().String(), "storage endpoint"); err != nil {
				return err
			}
		}
	}
	var lastErr error
	err := k8sretry.Wait(ctx, 500*time.Millisecond, 2*time.Minute, func(ctx context.Context) (bool, error) {
		lastErr = g.checkKubernetesNetwork(ctx, allocated)
		return lastErr == nil, lastErr
	})
	if err != nil && lastErr != nil {
		return errors.Wrapf(err, "Could not validate Cluster network: %s", lastErr)
	}
	return err
}

func (g *Genesis) checkKubernetesNetwork(ctx context.Context, allocated []netip.Prefix) error {
	nodes, err := g.k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, node := range nodes.Items {
		for _, cidr := range append([]string{node.Spec.PodCIDR}, node.Spec.PodCIDRs...) {
			if err := checkNetworkOverlap(allocated, cidr, "Kubernetes Pod CIDR on Node "+node.Name); err != nil {
				return err
			}
		}
		for _, addr := range node.Status.Addresses {
			if addr.Type == k8scorev1.NodeInternalIP || addr.Type == k8scorev1.NodeExternalIP {
				if err := checkNetworkOverlap(allocated, addr.Address, "Kubernetes Node "+node.Name); err != nil {
					return err
				}
			}
		}
	}
	cidrs, err := g.k8sC.NetworkingV1().ServiceCIDRs().List(ctx, k8smetav1.ListOptions{})
	if err != nil && !k8serr.IsNotFound(err) && !k8serr.IsMethodNotSupported(err) {
		return err
	}
	if err == nil {
		for _, cidr := range cidrs.Items {
			for _, value := range cidr.Spec.CIDRs {
				if err := checkNetworkOverlap(allocated, value, "Kubernetes ServiceCIDR "+cidr.Name); err != nil {
					return err
				}
			}
		}
	}
	services, err := g.k8sC.CoreV1().Services("").List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, service := range services.Items {
		for _, value := range append([]string{service.Spec.ClusterIP}, service.Spec.ClusterIPs...) {
			if value == k8scorev1.ClusterIPNone {
				continue
			}
			if err := checkNetworkOverlap(allocated, value, "Kubernetes Service "+service.Namespace+"/"+service.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkNetworkOverlap(allocated []netip.Prefix, value, source string) error {
	if value == "" {
		return nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, addrErr := netip.ParseAddr(value)
		if addrErr != nil {
			return errors.Errorf("Invalid network address %q from %s", value, source)
		}
		addr = addr.Unmap()
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return errors.Errorf("Invalid IPv4-mapped network %q from %s", value, source)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	for _, subnet := range allocated {
		if subnet.Overlaps(prefix) {
			return errors.Errorf("Cluster subnet %s overlaps %s %s", subnet, source, value)
		}
	}
	return nil
}
