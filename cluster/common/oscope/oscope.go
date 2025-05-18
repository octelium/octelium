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

package oscope

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/rgx"
	"github.com/pkg/errors"
)

func VerifyScopes(scopes []string) error {
	_, err := GetScopes(scopes)

	return err
}

func GetScopes(scopes []string) ([]*corev1.Scope, error) {
	var ret []*corev1.Scope
	if scopes != nil && len(scopes) == 0 {
		return nil, errors.Errorf("Scopes must not be an empty array")
	}
	if len(scopes) == 0 {
		return nil, nil
	}
	if len(scopes) > 128 {
		return nil, errors.Errorf("Too many scopes")
	}

	for _, scope := range scopes {
		scope, err := getScope(scope)
		if err != nil {
			return nil, err
		}
		ret = append(ret, scope)
	}

	return ret, nil
}

func getScope(scope string) (*corev1.Scope, error) {
	scopeLen := len(scope)
	if scopeLen <= 0 {
		return nil, errors.Errorf("Found empty scope")
	}
	if scopeLen > 256 {
		return nil, errors.Errorf("Scope is too large")
	}
	if !govalidator.IsASCII(scope) {
		return nil, errors.Errorf("Invalid scope format")
	}

	scopeParts := strings.SplitN(scope, ":", 2)
	if len(scopeParts) < 2 {
		return nil, errors.Errorf("Invalid scope")
	}
	switch scopeParts[0] {
	case "api":
		return getScopeAPI(scopeParts[1])
	case "service":
		return getScopeService(scopeParts[1])
	default:
		return nil, errors.Errorf("Invalid scope type")
	}

}

var apiRgx1 = regexp.MustCompile(`^(?P<api>[a-z0-9-]{1,64})$`)
var apiRgx2 = regexp.MustCompile(`^((?P<api>[a-z0-9-]{1,64})\.(?P<service>[a-zA-Z0-9-]+))$`)
var apiRgx3 = regexp.MustCompile(`^((?P<api>[a-z0-9-]{1,64})\.(?P<service>[a-zA-Z0-9-]+)\/(?P<method>[a-zA-Z0-9-]+))$`)

func getScopeAPI(arg string) (*corev1.Scope, error) {
	if arg == "" {
		return nil, errors.Errorf("API scope content is empty")
	}

	packageFromAPI := func(arg string) string {
		return fmt.Sprintf("octelium.api.main.%s.v1", arg)
	}

	switch {
	case arg == "*":
		return &corev1.Scope{
			Type: &corev1.Scope_Api{
				Api: &corev1.Scope_API{
					Type: &corev1.Scope_API_All_{
						All: &corev1.Scope_API_All{},
					},
				},
			},
		}, nil
	case apiRgx1.MatchString(arg):
		match := apiRgx1.FindStringSubmatch(arg)
		var api string
		for i, name := range apiRgx1.SubexpNames() {
			switch name {
			case "api":
				api = match[i]
			}
		}

		return &corev1.Scope{
			Type: &corev1.Scope_Api{
				Api: &corev1.Scope_API{
					Type: &corev1.Scope_API_Filter_{
						Filter: &corev1.Scope_API_Filter{
							Packages: []string{packageFromAPI(api)},
							Services: []string{"*"},
							Methods:  []string{"*"},
						},
					},
				},
			},
		}, nil
	case apiRgx2.MatchString(arg):
		match := apiRgx2.FindStringSubmatch(arg)
		var api, service string
		for i, name := range apiRgx2.SubexpNames() {
			switch name {
			case "api":
				api = match[i]
			case "service":
				service = match[i]
			}
		}

		return &corev1.Scope{
			Type: &corev1.Scope_Api{
				Api: &corev1.Scope_API{
					Type: &corev1.Scope_API_Filter_{
						Filter: &corev1.Scope_API_Filter{
							Packages: []string{packageFromAPI(api)},
							Services: []string{service},
							Methods:  []string{"*"},
						},
					},
				},
			},
		}, nil
	case apiRgx3.MatchString(arg):
		match := apiRgx3.FindStringSubmatch(arg)
		var api, service, method string
		for i, name := range apiRgx3.SubexpNames() {
			switch name {
			case "api":
				api = match[i]
			case "service":
				service = match[i]
			case "method":
				method = match[i]
			}
		}

		return &corev1.Scope{
			Type: &corev1.Scope_Api{
				Api: &corev1.Scope_API{
					Type: &corev1.Scope_API_Filter_{
						Filter: &corev1.Scope_API_Filter{
							Packages: []string{packageFromAPI(api)},
							Services: []string{service},
							Methods:  []string{method},
						},
					},
				},
			},
		}, nil
	}

	return nil, errors.Errorf("Could not parse scope: %s", arg)
}

var svcRgx1 = regexp.MustCompile(
	`^(?P<svc>[a-z][a-z0-9-]{0,28}[a-z0-9])\.(?P<ns>[a-z][a-z0-9-]{0,28}[a-z0-9])$`)
var svcRgx2 = regexp.MustCompile(
	`^(?P<ns>[a-z][a-z0-9-]{0,28}[a-z0-9])\/\*$`)

func getScopeService(arg string) (*corev1.Scope, error) {
	if arg == "" {
		return nil, errors.Errorf("API scope content is empty")
	}
	switch {
	case arg == "*":
		return &corev1.Scope{
			Type: &corev1.Scope_Service_{
				Service: &corev1.Scope_Service{
					Type: &corev1.Scope_Service_All_{
						All: &corev1.Scope_Service_All{},
					},
				},
			},
		}, nil
	case rgx.NameMain.MatchString(arg):
		return &corev1.Scope{
			Type: &corev1.Scope_Service_{
				Service: &corev1.Scope_Service{
					Type: &corev1.Scope_Service_Filter_{
						Filter: &corev1.Scope_Service_Filter{
							Names:      []string{arg},
							Namespaces: []string{"default"},
						},
					},
				},
			},
		}, nil
	case svcRgx1.MatchString(arg):
		match := svcRgx1.FindStringSubmatch(arg)
		var svc, ns string
		for i, name := range svcRgx1.SubexpNames() {
			switch name {
			case "svc":
				svc = match[i]
			case "ns":
				ns = match[i]
			}
		}

		return &corev1.Scope{
			Type: &corev1.Scope_Service_{
				Service: &corev1.Scope_Service{
					Type: &corev1.Scope_Service_Filter_{
						Filter: &corev1.Scope_Service_Filter{
							Names:      []string{svc},
							Namespaces: []string{ns},
						},
					},
				},
			},
		}, nil
	case svcRgx2.MatchString(arg):
		match := svcRgx2.FindStringSubmatch(arg)
		var ns string
		for i, name := range svcRgx2.SubexpNames() {
			switch name {
			case "ns":
				ns = match[i]
			}
		}

		return &corev1.Scope{
			Type: &corev1.Scope_Service_{
				Service: &corev1.Scope_Service{
					Type: &corev1.Scope_Service_Filter_{
						Filter: &corev1.Scope_Service_Filter{
							Names:      []string{"*"},
							Namespaces: []string{ns},
						},
					},
				},
			},
		}, nil
	}

	return nil, errors.Errorf("Invalid scope: %s", arg)
}

func IsAuthorizedByScopes(req *corev1.RequestContext) bool {

	if req.Session == nil {
		return false
	}

	if len(req.Session.Status.Scopes) == 0 {
		return true
	}

	return doIsAuthorizedByScopes(req.Session.Status.Scopes, req.Service, req.Request)
}

func doIsAuthorizedByScopes(scopes []*corev1.Scope, svc *corev1.Service, req *corev1.RequestContext_Request) bool {

	if len(scopes) == 0 {
		return true
	}

	for _, scope := range scopes {
		switch scope.Type.(type) {
		case *corev1.Scope_Service_:
			if IsAuthorizedByScopeService(scope.GetService(), svc, req) {
				return true
			}
		case *corev1.Scope_Api:
			if !ucorev1.ToService(svc).IsManagedService() &&
				svc.Status.ManagedService != nil &&
				svc.Status.ManagedService.Type == "apiserver" {
				continue
			}
			if req == nil || req.GetGrpc() == nil {
				continue
			}

			if IsAuthorizedByScopeAPIServer(scope.GetApi(), svc, req) {
				return true
			}

		default:
			continue
		}
	}

	return false
}

func IsAuthorizedByScopeAPIServer(scope *corev1.Scope_API, svc *corev1.Service, req *corev1.RequestContext_Request) bool {

	grpcReq := req.GetGrpc()

	switch scope.Type.(type) {
	case *corev1.Scope_API_All_:
		return true
	case *corev1.Scope_API_Filter_:
		filter := scope.GetFilter()

		if len(filter.Packages) > 0 {
			if !isInListOrAny(filter.Packages, grpcReq.Package) {
				return false
			}
		}

		if len(filter.Services) > 0 {
			if !isInListOrAny(filter.Services, grpcReq.Service) {
				return false
			}
		}

		if len(filter.Methods) > 0 {
			if !isInListOrAny(filter.Methods, grpcReq.Method) {
				return false
			}
		}

		return true
	default:
		return false
	}
}

func IsAuthorizedByScopeService(scope *corev1.Scope_Service, svc *corev1.Service, req *corev1.RequestContext_Request) bool {
	switch scope.Type.(type) {
	case *corev1.Scope_Service_All_:
		return true
	case *corev1.Scope_Service_Filter_:
		filter := scope.GetFilter()
		if len(filter.Names) > 0 {
			if !isInListOrAny(filter.Names, svc.Metadata.Name) {
				return false
			}
		}

		if len(filter.Namespaces) > 0 {
			if !isInListOrAny(filter.Namespaces, svc.Status.NamespaceRef.Name) {
				return false
			}
		}

		return true
	default:
		return false
	}
}

func isInList(lst []string, arg string) bool {
	for _, itm := range lst {
		if itm == arg {
			return true
		}
	}
	return false
}

func isInListOrAny(lst []string, arg string) bool {
	for _, itm := range lst {
		if itm == arg || itm == "*" {
			return true
		}
	}
	return false
}
