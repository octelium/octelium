package browserorigin

import (
	"net/url"
	"slices"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
)

type Host struct {
	Name            string
	AllowSubdomains bool
}

func SystemServiceHosts(domain string, services []*corev1.Service) []Host {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil
	}

	ret := make([]Host, 0, len(services))
	for _, svc := range services {
		if svc == nil || svc.Metadata == nil || !svc.Metadata.IsSystem ||
			svc.Spec == nil || !svc.Spec.IsPublic || svc.Status == nil ||
			svc.Status.NamespaceRef == nil || svc.Status.ManagedService == nil {
			continue
		}

		for _, host := range getPublicHosts(svc, domain) {
			candidate := Host{
				Name:            host,
				AllowSubdomains: svc.Status.ManagedService.HasSubdomain,
			}

			idx := slices.IndexFunc(ret, func(item Host) bool {
				return item.Name == candidate.Name
			})
			if idx < 0 {
				ret = append(ret, candidate)
			} else if candidate.AllowSubdomains {
				ret[idx].AllowSubdomains = true
			}
		}
	}

	slices.SortFunc(ret, func(a, b Host) int {
		return strings.Compare(a.Name, b.Name)
	})

	return ret
}

func getPublicHosts(svc *corev1.Service, domain string) []string {
	parts := strings.Split(svc.Metadata.Name, ".")
	name := parts[0]
	namespace := svc.Status.NamespaceRef.Name
	ret := []string{strings.ToLower(name + "." + namespace + "." + domain)}

	appendHost := func(host string) {
		host = strings.ToLower(host)
		if !slices.Contains(ret, host) {
			ret = append(ret, host)
		}
	}

	if name == "default" {
		appendHost(namespace + "." + domain)
	}
	if namespace == "default" {
		appendHost(name + "." + domain)
		if name == "default" {
			appendHost(domain)
		}
	}

	return ret
}

func IsAllowed(origin string, hosts []Host) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" ||
		u.Host != u.Hostname() || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}

	host := strings.ToLower(u.Hostname())
	for _, item := range hosts {
		if host == item.Name ||
			(item.AllowSubdomains && strings.HasSuffix(host, "."+item.Name)) {
			return true
		}
	}

	return false
}
