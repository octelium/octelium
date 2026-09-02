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
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/jsonschemautils"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/rscutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/utilnet"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/glob"
	"github.com/octelium/octelium/pkg/grpcerr"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"golang.org/x/net/http/httpguts"
)

func (s *Server) ListService(ctx context.Context, req *corev1.ListServiceOptions) (*corev1.ServiceList, error) {

	var err error

	var listOpts []*rmetav1.ListOptions_Filter

	if req.NamespaceRef != nil {
		if err := apivalidation.CheckObjectRef(req.NamespaceRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}
		ns, err := s.octeliumC.CoreC().GetNamespace(ctx, apivalidation.ObjectReferenceToRGetOptions(req.NamespaceRef))
		if err != nil {
			return nil, err
		}
		listOpts = append(listOpts, urscsrv.FilterFieldEQValStr("status.namespaceRef.uid", ns.Metadata.Uid))
	}

	if req.RegionRef != nil {
		if err := apivalidation.CheckObjectRef(req.RegionRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}
		rgn, err := s.octeliumC.CoreC().GetRegion(ctx, apivalidation.ObjectReferenceToRGetOptions(req.RegionRef))
		if err != nil {
			return nil, err
		}
		listOpts = append(listOpts, urscsrv.FilterFieldEQValStr("status.regionRef.uid", rgn.Metadata.Uid))
	}

	itemList, err := s.octeliumC.CoreC().ListService(ctx,
		urscsrv.GetPublicListOptions(req, listOpts...))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) UpdateService(ctx context.Context, req *corev1.Service) (*corev1.Service, error) {

	if err := apivalidation.ValidateCommon(req, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
			ParentsMax:  1,
		},
	}); err != nil {
		return nil, err
	}

	item, err := s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Name: vutils.GetServiceFullNameFromName(req.Metadata.Name),
		Uid:  req.Metadata.Uid,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	common.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec

	if err := s.validateService(ctx, item); err != nil {
		return nil, err
	}

	if err := s.setServiceMetadataStatus(ctx, item); err != nil {
		return nil, err
	}

	item, err = s.octeliumC.CoreC().UpdateService(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) DoCreateService(ctx context.Context, req *corev1.Service, isSystemService bool) (*corev1.Service, error) {

	if err := apivalidation.ValidateCommon(req, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
			ParentsMax:  1,
		},
	}); err != nil {
		return nil, err
	}

	nsName, err := getNamespace(req.Metadata.Name)
	if err != nil {
		return nil, err
	}

	ns, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: nsName})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, serr.InvalidArg("The Namespace %s does not exist", nsName)
		}
		return nil, serr.InternalWithErr(err)
	}

	{
		_, err := s.octeliumC.CoreC().GetService(ctx,
			&rmetav1.GetOptions{
				Name: vutils.GetServiceFullNameFromName(req.Metadata.Name),
			})
		if err == nil {
			return nil, grpcutils.AlreadyExists("The Service %s already exists in the Namespace: %s",
				req.Metadata.Name, ns.Metadata.Name)
		}
		if !grpcerr.IsNotFound(err) {
			return nil, grpcutils.InternalWithErr(err)
		}
	}

	item := &corev1.Service{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status: &corev1.Service_Status{
			NamespaceRef: umetav1.GetObjectReference(ns),
		},
	}

	if isSystemService && req.Status != nil {
		item.Status.ManagedService = req.Status.ManagedService
	}

	item.Metadata.Name = vutils.GetServiceFullNameFromName(item.Metadata.Name)

	if err := s.validateService(ctx, item); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	if err := s.setServiceMetadataStatus(ctx, item); err != nil {
		return nil, err
	}

	item.Metadata.IsSystem = isSystemService

	if isSystemService {
		item.Metadata.IsSystemHidden = req.Metadata.IsSystemHidden
		item.Metadata.IsUserHidden = req.Metadata.IsUserHidden

		if len(item.Metadata.SystemLabels) == 0 {
			item.Metadata.SystemLabels = req.Metadata.SystemLabels
		} else {
			for k, v := range req.Metadata.SystemLabels {
				item.Metadata.SystemLabels[k] = v
			}
		}

		if len(item.Metadata.SpecLabels) == 0 {
			item.Metadata.SpecLabels = req.Metadata.SpecLabels
		} else {
			for k, v := range req.Metadata.SpecLabels {
				item.Metadata.SpecLabels[k] = v
			}
		}
	}

	if !isSystemService && item.Status.NamespaceRef != nil && item.Status.NamespaceRef.Name == "default" {
		if _, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{
			Name: ucorev1.ToService(item).Name(),
		}); err == nil {
			return nil, grpcutils.InvalidArg(
				"You cannot use the Service name :%s in the default Namespace while having another Namespace with the same name",
				ucorev1.ToService(item).Name())
		} else if !grpcerr.IsNotFound(err) {
			return nil, grpcutils.InternalWithErr(err)
		}

	}

	createdSvc, err := s.octeliumC.CoreC().CreateService(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return createdSvc, nil
}

func (s *Server) CreateService(ctx context.Context, req *corev1.Service) (*corev1.Service, error) {
	return s.DoCreateService(ctx, req, false)
}

func (s *Server) DeleteService(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, &apivalidation.CheckGetOptionsOpts{
		ParentsMax: 1,
	}); err != nil {
		return nil, err
	}

	svc, err := s.octeliumC.CoreC().GetService(ctx,
		&rmetav1.GetOptions{
			Name: vutils.GetServiceFullNameFromName(req.Name),
			Uid:  req.Uid,
		},
	)
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(svc); err != nil {
		return nil, err
	}

	ret := &metav1.OperationResult{}

	_, err = s.octeliumC.CoreC().DeleteService(ctx, apivalidation.ObjectToRDeleteOptions(svc))
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return ret, nil
}

func (s *Server) validateService(ctx context.Context,
	svc *corev1.Service) error {

	if err := apivalidation.ValidateCommon(svc, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
			ParentsMax:  1,
		},
	}); err != nil {
		return err
	}

	if svc.Spec == nil {
		return grpcutils.InvalidArg("You must provide spec")
	}

	spec := svc.Spec

	if err := apivalidation.ValidateAttrs(spec.Attrs); err != nil {
		return err
	}

	switch svc.Spec.Mode {
	case corev1.Service_Spec_MODE_UNSET:
		return grpcutils.InvalidArg("Service mode must be set")
	}

	if spec.Port != 0 {
		if err := apivalidation.ValidatePort(int(spec.Port)); err != nil {
			return err
		}
	}

	if svc.Spec.Region != "" {
		_, err := s.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: svc.Spec.Region})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return serr.InvalidArg("The Region %s does not exist", svc.Spec.Region)
			}
			return serr.InternalWithErr(err)
		}
	}

	if svc.Spec.Authorization != nil {
		if err := s.validatePolicyOwner(ctx, svc.Spec.Authorization); err != nil {
			return err
		}
	}

	if spec.Config != nil {
		switch spec.Config.Name {
		case "", "default":
		default:
			return serr.InvalidArg("The name of the default Config cannot be set to: %s", spec.Config.Name)
		}

		if spec.Config.Parent != "" {
			return grpcutils.InvalidArg("Default config cannot have a parent")
		}

		if err := s.validateServiceConfig(ctx, spec.Config, svc, false); err != nil {
			return err
		}
	}

	if spec.DynamicConfig != nil {
		if len(spec.DynamicConfig.Configs) > 1000 {
			return serr.InvalidArg("Too many dynamic named Configs")
		}
		if len(spec.DynamicConfig.Rules) > 1000 {
			return serr.InvalidArg("Too many dynamic Config rules")
		}

		names := []string{"default"}
		for _, cfg := range spec.DynamicConfig.Configs {
			if err := apivalidation.ValidateName(cfg.Name, 0, 0); err != nil {
				return err
			}
			if slices.Contains(names, cfg.Name) {
				return serr.InvalidArg("This Config name already exists: %s", cfg.Name)
			}

			names = append(names, cfg.Name)

			if err := s.validateServiceConfig(ctx, cfg, svc, false); err != nil {
				return err
			}
		}

		for _, rule := range spec.DynamicConfig.Rules {
			if rule.Condition == nil {
				return serr.InvalidArg("DynamicConfig rule Condition must be set")
			}
			if err := s.validateCondition(ctx, rule.Condition); err != nil {
				return err
			}

			switch rule.Type.(type) {
			case *corev1.Service_Spec_DynamicConfig_Rule_ConfigName:
				if err := apivalidation.ValidateName(rule.GetConfigName(), 0, 0); err != nil {
					return err
				}
			case *corev1.Service_Spec_DynamicConfig_Rule_Eval:
				if err := checkCELExpressionMap(ctx, rule.GetEval()); err != nil {
					return grpcutils.InvalidArg("Invalid eval: %s", rule.GetEval())
				}
			case *corev1.Service_Spec_DynamicConfig_Rule_Opa:
				if err := checkOPAMapAny(ctx, rule.GetOpa()); err != nil {
					return grpcutils.InvalidArg("Invalid OPA script: %s", rule.GetOpa())
				}
			default:
				return grpcutils.InvalidArg("You must provide either a config name or eval")
			}

		}
	}

	if svc.Spec.IsPublic && !ucorev1.ToService(svc).IsHTTP() {
		return serr.InvalidArg("The Service: %s is not an HTTP-based Service to be exposed publicly.", svc.Metadata.Name)
	}

	if !ldflags.IsTest() {
		reservedPorts := []uint32{
			uint32(vutils.HealthCheckPortVigil),
			uint32(vutils.HealthCheckPortManagedService),
		}

		if slices.Contains(reservedPorts, svc.Status.Port) {
			return grpcutils.InvalidArg("This Service port number is reserved by the Cluster: %d", svc.Status.Port)
		}
	}

	if svc.Status == nil || !ucorev1.ToService(svc).IsManagedService() {
		switch {
		case svc.Spec.Config == nil && svc.Spec.DynamicConfig == nil:
			return grpcutils.InvalidArg(
				"There must be at least a Config, a named dynamic Config or an evaluated dynamic Config")
		case svc.Spec.DynamicConfig != nil:
			if len(svc.Spec.DynamicConfig.Configs) == 0 &&
				!slices.ContainsFunc(svc.Spec.DynamicConfig.Rules,
					func(itm *corev1.Service_Spec_DynamicConfig_Rule) bool {
						switch itm.Type.(type) {
						case *corev1.Service_Spec_DynamicConfig_Rule_Eval,
							*corev1.Service_Spec_DynamicConfig_Rule_Opa:
							return true
						default:
							return false
						}
					}) {
				return grpcutils.InvalidArg(
					"There must be at a named dynamic Config or an evaluated dynamic Config in your dynamic Configuration")
			}
		}

	}

	if svc.Spec.IsAnonymous {
		if !svc.Spec.IsPublic {
			return grpcutils.InvalidArg("Anonymous access mode requires isPublic to be enabled")
		}
		switch svc.Spec.Mode {
		case corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB,
			corev1.Service_Spec_GRPC, corev1.Service_Spec_MCP,
			corev1.Service_Spec_LLM:
		default:
			return grpcutils.InvalidArg(
				"Anonymous access mode requires HTTP, WEB, GRPC, MCP or LLM modes")
		}
		if svc.Spec.Authorization != nil && !svc.Spec.Authorization.EnableAnonymous {
			return grpcutils.InvalidArg(
				"Anonymous access mode requires no authorization configuration or enabling EnableAnonymous")
		}
	}

	if svc.Spec.Authorization != nil && svc.Spec.Authorization.EnableAnonymous && !svc.Spec.IsAnonymous {
		return grpcutils.InvalidArg("Only anonymous Services can enable anonymous authorization")
	}

	return nil
}

func (s *Server) ValidateServiceConfig(ctx context.Context,
	cfg *corev1.Service_Spec_Config, svc *corev1.Service, skipRscCheck bool) error {
	return s.validateServiceConfig(ctx, cfg, svc, skipRscCheck)
}

func (s *Server) validateServiceConfig(ctx context.Context,
	cfg *corev1.Service_Spec_Config, svc *corev1.Service, skipRscCheck bool) error {

	if cfg == nil {
		return grpcutils.InvalidArg("Config is not set")
	}

	octeliumC := s.octeliumC
	spec := svc.Spec

	cfgNames := func() []string {
		if spec.DynamicConfig == nil || len(spec.DynamicConfig.Configs) < 1 {
			return nil
		}

		var ret []string
		for _, cfg := range spec.DynamicConfig.Configs {
			ret = append(ret, cfg.Name)
		}

		return ret
	}()

	if cfg.Parent != "" {
		if cfg.Parent == cfg.Name {
			return grpcutils.InvalidArg("Config parent cannot have the Config name")
		}
		switch cfg.Parent {
		case "default", "":
		default:
			if idx := slices.Index(cfgNames, cfg.Parent); idx < 0 {
				return grpcutils.InvalidArg("Parent config name: %s does not exist", cfg.Parent)
			}
		}

		cfg = rscutils.GetMergedServiceConfig(cfg, svc)
	}

	if cfg.Tls != nil {
		if len(cfg.Tls.TrustedCAs) > 0 {
			if len(cfg.Tls.TrustedCAs) > 32 {
				return grpcutils.InvalidArg("Too many trusted CAs")
			}

			for _, ca := range cfg.Tls.TrustedCAs {
				_, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(ca))
				if err != nil {
					return grpcutils.InvalidArg("Invalid trusted CA PEM")
				}
			}
		}

		if cfg.Tls.ClientCertificate != nil {
			if err := s.validateSecretOwner(ctx, cfg.Tls.ClientCertificate); err != nil {
				return err
			}
		}
	}

	if cfg.ClientCertificate != nil {
		if err := s.validateSecretOwner(ctx, cfg.ClientCertificate); err != nil {
			return err
		}

		if len(cfg.ClientCertificate.TrustedCAs) > 0 {
			if len(cfg.ClientCertificate.TrustedCAs) > 32 {
				return grpcutils.InvalidArg("Too many trusted CAs")
			}

			for _, ca := range cfg.ClientCertificate.TrustedCAs {
				_, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(ca))
				if err != nil {
					return grpcutils.InvalidArg("Invalid trusted CA PEM")
				}
			}
		}
	}

	if cfg.Upstream != nil {

		backendPorts := []int{}
		backendSchemes := []string{}

		checkURL := func(u string) error {
			if u == "" {
				return grpcutils.InvalidArg("URL is empty")
			}

			if len(u) > 2048 {
				return grpcutils.InvalidArg("URL is too long: %s", u)
			}

			backendURL, err := url.Parse(u)
			if err != nil {
				return grpcutils.InvalidArg("Invalid upstream URL: %s", u)
			}

			if backendURL.Scheme == "" {
				return grpcutils.InvalidArg("No scheme set in the upstream URL")
			}

			backendSchemes = append(backendSchemes, backendURL.Scheme)

			if backendURL.Port() != "" {
				portnum, err := strconv.Atoi(backendURL.Port())
				if err != nil {
					return grpcutils.InvalidArg("Invalid port %+v", err)
				}
				if err := apivalidation.ValidatePort(portnum); err != nil {
					return err
				}
				backendPorts = append(backendPorts, portnum)

			} else {
				portnum, err := utilnet.GetPortFromScheme(backendURL.Scheme)
				if err != nil {
					return grpcutils.InvalidArg("Provide the port number in the backend URL: %s", u)
				}
				backendPorts = append(backendPorts, portnum)
			}
			return nil
		}

		if cfg.Upstream.User != "" {
			_, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: cfg.Upstream.User})
			if err != nil {
				if grpcerr.IsNotFound(err) {
					return serr.InvalidArg("The upstream User %s does not exist", cfg.Upstream.User)
				}
				return serr.InternalWithErr(err)
			}
		}

		switch cfg.Upstream.Type.(type) {
		case *corev1.Service_Spec_Config_Upstream_Url:
			if err := checkURL(cfg.Upstream.GetUrl()); err != nil {
				return err
			}
		case *corev1.Service_Spec_Config_Upstream_Loadbalance_:

			eps := cfg.Upstream.GetLoadbalance().Endpoints

			if len(eps) == 0 {
				return grpcutils.InvalidArg("There must be at least 1 endpoint in loadBalance")
			}

			if len(eps) > 100 {
				return grpcutils.InvalidArg("Too many endpoints: %d in loadBalance", len(eps))
			}

			for _, ep := range eps {

				if err := checkURL(ep.Url); err != nil {
					return err
				}

				if ep.User != "" {
					_, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: ep.User})
					if err != nil {
						if grpcerr.IsNotFound(err) {
							return serr.InvalidArg("The upstream User %s does not exist", ep.User)
						}
						return serr.InternalWithErr(err)
					}
				}

			}

		case *corev1.Service_Spec_Config_Upstream_Container_:
			typ := cfg.Upstream.GetContainer()

			if typ.Image == "" {
				return grpcutils.InvalidArg("You must provide a managedContainer image")
			}
			if len(typ.Image) > 256 {
				return grpcutils.InvalidArg("Image address is too long: %s", typ.Image)
			}

			if err := apivalidation.ValidatePort(int(typ.Port)); err != nil {
				return err
			}

			if len(typ.Args) > 64 {
				return grpcutils.InvalidArg("Too many managedContainer args")
			}

			if len(typ.Command) > 64 {
				return grpcutils.InvalidArg("Too many command items")
			}

			for _, arg := range typ.Args {
				if len(arg) > 1024 {
					return grpcutils.InvalidArg("Too long managedContainer arg: %s", arg)
				}
			}

			for _, arg := range typ.Command {
				if len(arg) > 1024 {
					return grpcutils.InvalidArg("Too long managedContainer command: %s", arg)
				}
			}

			if typ.Replicas > 100 {
				return grpcutils.InvalidArg("Too many managedContainer replicas: %d", typ.Replicas)
			}

			if len(typ.Env) > 32 {
				return grpcutils.InvalidArg("Too many environment variable")
			}
			for _, itm := range typ.Env {
				if err := apivalidation.ValidateEnvVarKey(itm.Name); err != nil {
					return err
				}

				switch itm.Type.(type) {
				case *corev1.Service_Spec_Config_Upstream_Container_Env_Value:
					if len(itm.GetValue()) > 2048 {
						return grpcutils.InvalidArg("env var value is too long")
					}
				case *corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret:
					if err := s.validateSecretOwner(ctx, itm); err != nil {
						return err
					}
				case *corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef_:
					if itm.GetKubernetesSecretRef().Name == "" {
						return grpcutils.InvalidArg("KubernetesSecretRef name is empty")
					}
					if itm.GetKubernetesSecretRef().Key == "" {
						return grpcutils.InvalidArg("KubernetesSecretRef key is empty")
					}
					if err := apivalidation.ValidateGenASCII(itm.GetKubernetesSecretRef().Name); err != nil {
						return err
					}
					if err := apivalidation.ValidateGenASCII(itm.GetKubernetesSecretRef().Key); err != nil {
						return err
					}
				default:
					return grpcutils.InvalidArg("either value, fromSecret or kubernetesSecretRef must be set")
				}

			}

			if typ.ResourceLimit != nil {
				if len(typ.ResourceLimit.Ext) > 100 {
					return grpcutils.InvalidArg("Too many extend resources")
				}

				for k, v := range typ.ResourceLimit.Ext {

					if err := apivalidation.ValidateGenASCII(k); err != nil {
						return err
					}

					if err := apivalidation.ValidateGenASCII(v); err != nil {
						return err
					}
				}
			}

			if typ.SecurityContext != nil {
				if typ.SecurityContext.Capabilities != nil {
					for _, cap := range typ.SecurityContext.Capabilities.Add {
						if !k8sCapabilityRegex.MatchString(cap) {
							return grpcutils.InvalidArg("Invalid capability: %s", cap)
						}
					}

					for _, cap := range typ.SecurityContext.Capabilities.Drop {
						if !k8sCapabilityRegex.MatchString(cap) {
							return grpcutils.InvalidArg("Invalid capability: %s", cap)
						}
					}
				}
			}

			if typ.GetCredentials() != nil && typ.GetCredentials().GetUsernamePassword() != nil {
				uP := typ.GetCredentials().GetUsernamePassword()
				if uP.Username == "" || len(uP.Username) > 256 {
					return grpcutils.InvalidArg("Invalid credentials username")
				}
				if uP.GetPassword() == nil {
					return grpcutils.InvalidArg("Password must be supplied")
				}
				if err := s.validateSecretOwner(ctx, uP.GetPassword()); err != nil {
					return err
				}
				if uP.Server != "" && !govalidator.IsDNSName(uP.Server) {
					return grpcutils.InvalidArg("Invalid server: %s", uP.Server)
				}
			}

			if len(typ.Volumes) > 32 {
				return grpcutils.InvalidArg("Too many volumes")
			}

			for _, vol := range typ.Volumes {
				if err := apivalidation.ValidateName(vol.Name, 0, 0); err != nil {
					return err
				}

				switch vol.Type.(type) {
				case *corev1.Service_Spec_Config_Upstream_Container_Volume_PersistentVolumeClaim_:
					if err := apivalidation.ValidateName(vol.GetPersistentVolumeClaim().Name, 0, 0); err != nil {
						return err
					}
				default:
					return grpcutils.InvalidArg("Volume type must be set")
				}
			}

			if len(typ.VolumeMounts) > 32 {
				return grpcutils.InvalidArg("Too many volumeMounts")
			}

			for _, mount := range typ.VolumeMounts {
				if err := apivalidation.ValidateName(mount.Name, 0, 0); err != nil {
					return err
				}

				if !govalidator.IsUnixFilePath(mount.MountPath) {
					return grpcutils.InvalidArg("Invalid mountPath: %s", mount.MountPath)
				}

				if err := s.validateGenStr(mount.SubPath, false, "subPath"); err != nil {
					return err
				}
			}

			validateProbe := func(p *corev1.Service_Spec_Config_Upstream_Container_Probe) error {
				if p == nil {
					return nil
				}

				switch p.Type.(type) {
				case *corev1.Service_Spec_Config_Upstream_Container_Probe_Grpc:
					if err := apivalidation.ValidatePort(int(p.GetGrpc().Port)); err != nil {
						return err
					}
				case *corev1.Service_Spec_Config_Upstream_Container_Probe_HttpGet:
					if len(p.GetHttpGet().Path) > 512 {
						return grpcutils.InvalidArg("Path is too long: %s", p.GetHttpGet().Path)
					}
					if !govalidator.IsRequestURI(p.GetHttpGet().Path) {
						return grpcutils.InvalidArg("Invalid path: %s", p.GetHttpGet().Path)
					}

					if err := apivalidation.ValidatePort(int(p.GetHttpGet().Port)); err != nil {
						return err
					}
				case *corev1.Service_Spec_Config_Upstream_Container_Probe_TcpSocket:
					if err := apivalidation.ValidatePort(int(p.GetTcpSocket().Port)); err != nil {
						return err
					}
				default:
					return grpcutils.InvalidArg("Invalid Probe type")
				}

				return nil
			}

			if err := validateProbe(typ.ReadinessProbe); err != nil {
				return err
			}

			if err := validateProbe(typ.LivenessProbe); err != nil {
				return err
			}
		default:
			return serr.InvalidArg("Invalid upstream type")
		}

		if len(backendSchemes) > 1 {
			for _, itm := range backendSchemes[1:] {
				if itm != backendSchemes[0] {
					return grpcutils.InvalidArg("All backend URL schemes must be identical")
				}
			}
		}
		if spec.Port == 0 && len(backendPorts) > 1 {
			for _, itm := range backendPorts[1:] {
				if itm != backendPorts[0] {
					return grpcutils.InvalidArg("If you do not explicitly provide a listener port then all backend URL ports must be identical")
				}
			}
		}
	}

	switch cfg.Type.(type) {

	case *corev1.Service_Spec_Config_Http:

		switch spec.Mode {
		case corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB, corev1.Service_Spec_GRPC:
		default:
			return grpcutils.InvalidArg("Either HTTP, WEB or GRPC modes must be set for HTTP config to be used")
		}

		if err := s.validateHTTPHeader(ctx, cfg.GetHttp().Header); err != nil {
			return err
		}

		if err := s.validateHTTPAuth(ctx, cfg.GetHttp().Auth); err != nil {
			return err
		}

		if cfg.GetHttp().Body != nil {
			body := cfg.GetHttp().Body

			if body.Validation != nil {
				switch body.Validation.Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Body_Validation_JsonSchema:
					switch body.Validation.GetJsonSchema().Type.(type) {
					case *corev1.Service_Spec_Config_HTTP_Body_Validation_JSONSchema_Inline:
						val := body.Validation.GetJsonSchema().GetInline()
						if len(val) == 0 {
							return grpcutils.InvalidArg("jsonSchema is empty")
						}
						if len(val) > 30000 {
							return grpcutils.InvalidArg("jsonSchema is too large")
						}
						if _, err := jsonschemautils.Compile([]byte(val)); err != nil {
							return grpcutils.InvalidArg("invalid jsonSchema")
						}

					default:
						return grpcutils.InvalidArg("Invalid jsonSchema type. Currently it must be set to inline.")
					}
				default:
					return grpcutils.InvalidArg("Invalid validation type")
				}
			}
		}

		if err := s.validateHTTPPath(cfg.GetHttp().Path); err != nil {
			return err
		}

		if cfg.GetHttp().Retry != nil {
			retry := cfg.GetHttp().Retry
			if retry.MaxRetries > 100 {
				return grpcutils.InvalidArg("Too many maxRetries: %d", retry.MaxRetries)
			}
			for _, d := range []*metav1.Duration{retry.InitialInterval, retry.MaxInterval, retry.MaxElapsedTime} {
				if d != nil {
					if err := apivalidation.ValidateDuration(d); err != nil {
						return err
					}
				}
			}
			if len(retry.StatusCodes) > 64 {
				return grpcutils.InvalidArg("Too many retry statusCodes")
			}
			for _, code := range retry.StatusCodes {
				if err := apivalidation.ValidateHTTPStatusCode(int64(code)); err != nil {
					return err
				}
			}
		}

		if cfg.GetHttp().Response != nil {
			resp := cfg.GetHttp().Response
			switch resp.Type.(type) {
			case *corev1.Service_Spec_Config_HTTP_Response_Direct_:
				if resp.GetDirect().StatusCode != 0 {
					if resp.GetDirect().StatusCode < 200 || resp.GetDirect().StatusCode > 599 {
						return grpcutils.InvalidArg("Invalid statusCode: %d", resp.GetDirect().StatusCode)
					}
				}
				if resp.GetDirect().ContentType != "" {
					if len(resp.GetDirect().ContentType) > 128 {
						return grpcutils.InvalidArg("contentType is too large")
					}

					if _, _, err := mime.ParseMediaType(resp.GetDirect().ContentType); err != nil {
						return grpcutils.InvalidArg("Invalid contentType")
					}
				}
				switch resp.GetDirect().Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Response_Direct_Inline:
					if len(resp.GetDirect().GetInline()) > 50000 {
						return grpcutils.InvalidArg("inline is too large")
					}
				case *corev1.Service_Spec_Config_HTTP_Response_Direct_InlineBytes:
					if len(resp.GetDirect().GetInlineBytes()) > 35000 {
						return grpcutils.InvalidArg("inlineBytes is too large")
					}
				default:
					return grpcutils.InvalidArg("Invalid direct type")
				}
			default:
				return grpcutils.InvalidArg("Invalid response type")
			}
		}

		if err := s.validateHTTPPlugins(ctx, cfg.Name, cfg.GetHttp().Plugins); err != nil {
			return err
		}

		if err := s.validateHTTPVisibility(cfg.GetHttp().Visibility); err != nil {
			return err
		}

	case *corev1.Service_Spec_Config_Kubernetes_:
		if spec.Mode != corev1.Service_Spec_KUBERNETES {
			return grpcutils.InvalidArg("KUBERNETES mode must be set for KUBERNETES config to be used")
		}

		k8s := cfg.GetKubernetes()

		switch k8s.Type.(type) {
		case *corev1.Service_Spec_Config_Kubernetes_Kubeconfig_:
			if k8s.GetKubeconfig().GetFromSecret() == "" {
				return serr.InvalidArg("Kubeconfig secret name must be set")
			}
			sec, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: k8s.GetKubeconfig().GetFromSecret()})
			if err != nil {
				if grpcerr.IsNotFound(err) {
					return serr.InvalidArg("The Secret %s does not exist", k8s.GetKubeconfig().GetFromSecret())
				}
				return serr.InternalWithErr(err)
			}

			kubeconfig, err := k8sutils.UnmarshalKubeConfigFromYAML(ucorev1.ToSecret(sec).GetValueBytes())
			if err != nil {
				return serr.InvalidArg("Could not parse Kubeconfig form the Secret: %s", k8s.GetKubeconfig().GetFromSecret())
			}

			if clstr := kubeconfig.GetCluster(k8s.GetKubeconfig().Context); clstr == nil {
				return serr.InvalidArg("No Cluster found in the Kubeconfig")
			}

			if usr := kubeconfig.GetUser(k8s.GetKubeconfig().Context); usr == nil {
				return serr.InvalidArg("No User found in the Kubeconfig")
			}

		case *corev1.Service_Spec_Config_Kubernetes_ClientCertificate:
			if err := s.validateSecretOwner(ctx, k8s.GetClientCertificate()); err != nil {
				return err
			}
		case *corev1.Service_Spec_Config_Kubernetes_BearerToken_:

			if err := s.validateSecretOwner(ctx, k8s.GetBearerToken()); err != nil {
				return err
			}

		default:
			return serr.InvalidArg("Unsupported kubernetes config type")
		}

	case *corev1.Service_Spec_Config_Socks5:
		if spec.Mode != corev1.Service_Spec_SOCKS5 {
			return grpcutils.InvalidArg("SOCKS5 mode must be set for SOCKS5 config to be used")
		}
		inSocks5 := cfg.GetSocks5()

		if inSocks5.Auth != nil {
			switch inSocks5.Auth.Type.(type) {
			case *corev1.Service_Spec_Config_SOCKS5_Auth_UsernamePassword_:

				if inSocks5.Auth.GetUsernamePassword().Username != "" {
					if err := apivalidation.ValidateGenASCII(inSocks5.Auth.GetUsernamePassword().Username); err != nil {
						return err
					}
				}

				if err := s.validateSecretOwner(ctx, inSocks5.Auth.GetUsernamePassword().Password); err != nil {
					return err
				}

			}
		}
	case *corev1.Service_Spec_Config_Mcp:
		if spec.Mode != corev1.Service_Spec_MCP {
			return grpcutils.InvalidArg("MCP mode must be set for MCP config to be used")
		}

		if err := s.validateMCPConfig(ctx, cfg); err != nil {
			return err
		}

	case *corev1.Service_Spec_Config_Llm:
		if spec.Mode != corev1.Service_Spec_LLM {
			return grpcutils.InvalidArg("LLM mode must be set for LLM config to be used")
		}

		if err := s.validateLLMConfig(ctx, cfg); err != nil {
			return err
		}

	case *corev1.Service_Spec_Config_Rdp:
		if spec.Mode != corev1.Service_Spec_RDP && spec.Mode != corev1.Service_Spec_RDP_WEB {
			return grpcutils.InvalidArg("RDP or RDP_WEB mode must be set for RDP config to be used")
		}
		rdp := cfg.GetRdp()
		if rdp.GetAuth() != nil && rdp.GetAuth().GetPassword() != nil {
			if err := s.validateSecretOwner(ctx, rdp.GetAuth().GetPassword()); err != nil {
				return err
			}
		}
	case *corev1.Service_Spec_Config_Ssh:
		if spec.Mode != corev1.Service_Spec_SSH {
			return grpcutils.InvalidArg("SSH mode must be set for SSH config to be used")
		}
		inSSH := cfg.GetSsh()

		if inSSH.Auth != nil {
			switch inSSH.Auth.Type.(type) {
			case *corev1.Service_Spec_Config_SSH_Auth_Password_:
				if err := s.validateSecretOwner(ctx, inSSH.Auth.GetPassword()); err != nil {
					return err
				}
			case *corev1.Service_Spec_Config_SSH_Auth_PrivateKey_:
				if err := s.validateSecretOwner(ctx, inSSH.Auth.GetPrivateKey()); err != nil {
					return err
				}
			}
		}

	case *corev1.Service_Spec_Config_Postgres_:
		if spec.Mode != corev1.Service_Spec_POSTGRES {
			return grpcutils.InvalidArg("POSTGRES mode must be set for PostgreSQL config to be used")
		}

		pg := cfg.GetPostgres()

		if pg.User != "" {
			if err := apivalidation.ValidateGenASCII(pg.User); err != nil {
				return err
			}
		}
		if pg.GetAuth() != nil && pg.GetAuth().GetPassword() != nil {
			if err := s.validateSecretOwner(ctx, pg.GetAuth().GetPassword()); err != nil {
				return err
			}
		}

		if pg.Database != "" {
			if err := apivalidation.ValidateGenASCII(pg.Database); err != nil {
				return err
			}
		}
	case *corev1.Service_Spec_Config_Mysql:
		if spec.Mode != corev1.Service_Spec_MYSQL {
			return grpcutils.InvalidArg("MYSQL mode must be set for MySQL config to be used")
		}

		mysql := cfg.GetMysql()

		if mysql.User != "" {
			if err := apivalidation.ValidateGenASCII(mysql.User); err != nil {
				return err
			}
		}
		if mysql.GetAuth() != nil && mysql.GetAuth().GetPassword() != nil {
			if err := s.validateSecretOwner(ctx, mysql.GetAuth().GetPassword()); err != nil {
				return err
			}
		}

		if mysql.Database != "" {
			if err := apivalidation.ValidateGenASCII(mysql.Database); err != nil {
				return err
			}
		}
	}

	if spec.Deployment != nil {
		if spec.Deployment.Replicas > 100 {
			return grpcutils.InvalidArg("Too many replicas: %d", spec.Deployment.Replicas)

		}
	}

	return nil

}

func (s *Server) setServiceMetadataStatus(ctx context.Context, svc *corev1.Service) error {

	svc.Metadata.SpecLabels = make(map[string]string)
	specLabels := svc.Metadata.SpecLabels

	setHostUser := func(name string) error {
		usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: name})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return serr.InvalidArg("The upstream User %s does not exist", name)
			}
			return serr.InternalWithErr(err)
		}

		specLabels[fmt.Sprintf("host-user-%s", usr.Metadata.Name)] = usr.Metadata.Uid

		return nil
	}

	setCfgHostUser := func(cfg *corev1.Service_Spec_Config) error {
		if cfg == nil || cfg.Upstream == nil {
			return nil
		}

		switch cfg.Upstream.Type.(type) {
		case *corev1.Service_Spec_Config_Upstream_Url:
			if cfg.Upstream.User != "" {
				if err := setHostUser(cfg.Upstream.User); err != nil {
					return err
				}
			}
		case *corev1.Service_Spec_Config_Upstream_Loadbalance_:
			for _, itm := range cfg.Upstream.GetLoadbalance().Endpoints {
				if itm.User != "" {
					if err := setHostUser(itm.User); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

	setCfgK8s := func(cfg *corev1.Service_Spec_Config) error {

		if cfg.GetKubernetes() == nil || cfg.GetKubernetes().GetKubeconfig() == nil {
			return nil
		}
		k8s := cfg.GetKubernetes()

		sec, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: k8s.GetKubeconfig().GetFromSecret()})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return serr.InvalidArg("The Secret %s does not exist", k8s.GetKubeconfig().GetFromSecret())
			}
			return serr.InternalWithErr(err)
		}

		kubeconfig, err := k8sutils.UnmarshalKubeConfigFromYAML(ucorev1.ToSecret(sec).GetValueBytes())
		if err != nil {
			return serr.InvalidArg("Could not parse Kubeconfig form the Secret: %s", k8s.GetKubeconfig().GetFromSecret())
		}

		if clstr := kubeconfig.GetCluster(k8s.GetKubeconfig().Context); clstr == nil {
			return serr.InvalidArg("No Cluster found in the Kubeconfig")
		} else {
			specLabels[fmt.Sprintf("k8s-kubeconfig-url-%s", ucorev1.ToServiceConfig(cfg).GetRealName())] = clstr.Cluster.Server
		}

		if usr := kubeconfig.GetUser(k8s.GetKubeconfig().Context); usr == nil {
			return serr.InvalidArg("No User found in the Kubeconfig")
		} else {

			/*
				if usr.User.Token != "" {
					specLabels[fmt.Sprintf("k8s-kubeconfig-has-token-%s", ucorev1.ToServiceConfig(cfg).GetRealName())] = "true"
				}
			*/
		}
		return nil
	}

	if svc.Spec.Config != nil {
		if err := setCfgHostUser(svc.Spec.Config); err != nil {
			return err
		}

		if svc.Spec.Config.GetKubernetes() != nil {
			if err := setCfgK8s(svc.Spec.Config); err != nil {
				return err
			}
		}
	}

	if svc.Spec.DynamicConfig != nil {
		for _, cfg := range svc.Spec.DynamicConfig.Configs {
			if err := setCfgHostUser(cfg); err != nil {
				return err
			}

			if cfg.GetKubernetes() != nil {
				if err := setCfgK8s(cfg); err != nil {
					return err
				}
			}
		}
	}

	svc.Status.PrimaryHostname = func() string {
		s := ucorev1.ToService(svc)

		name := s.Name()
		ns := s.Namespace()

		switch {
		case name == "default" && ns == "default":
			return ""
		case ns == "default":
			return name
		case name == "default":
			return ns
		default:
			return fmt.Sprintf("%s.%s", name, ns)
		}
	}()

	svc.Status.AdditionalHostnames = func() []string {
		s := ucorev1.ToService(svc)

		name := s.Name()
		ns := s.Namespace()

		switch {
		case name == "default" && ns == "default":
			return []string{"default.default"}
		case ns == "default":
			return []string{fmt.Sprintf("%s.default", name)}
		case name == "default":
			return []string{fmt.Sprintf("default.%s", ns)}
		default:
			return nil
		}
	}()

	svc.Status.Port = func() uint32 {
		if svc.Spec.Port != 0 {
			return svc.Spec.Port
		}

		l := ucorev1.ToService(svc)

		if l.IsESSH() {
			return 22
		}

		if l.Spec.Mode == corev1.Service_Spec_RDP_WEB {
			return 8080
		}

		if l.IsManagedService() {
			return 8080
		}

		upstreamPort := l.UpstreamRealPort()

		if !l.Spec.IsTLS && l.IsHTTP() && upstreamPort == 443 {
			return 80
		}

		if upstreamPort != 0 && apivalidation.ValidatePort(upstreamPort) == nil {
			return uint32(upstreamPort)
		}

		switch l.Spec.Mode {
		case corev1.Service_Spec_TCP,
			corev1.Service_Spec_UDP,
			corev1.Service_Spec_MODE_UNSET:
			return 0
		case corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB, corev1.Service_Spec_MCP,
			corev1.Service_Spec_LLM:
			if l.Spec.IsTLS {
				return 443
			}
			return 80
		case corev1.Service_Spec_SSH:
			return 22
		case corev1.Service_Spec_DNS:
			return 53
		case corev1.Service_Spec_POSTGRES:
			return 5432
		case corev1.Service_Spec_MYSQL:
			return 3306
		case corev1.Service_Spec_SOCKS5:
			return 1080
		case corev1.Service_Spec_RDP:
			return 3389
		default:
			return 0
		}
	}()

	if svc.Status.Port == 0 {
		return grpcutils.InvalidArg("Service port number needs to be explicitly specified")
	}

	if svc.Spec.Region != "" {
		rgn, err := s.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: svc.Spec.Region})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return serr.InvalidArg("The Region %s does not exist", svc.Spec.Region)
			}
			return serr.InternalWithErr(err)
		}

		svc.Status.RegionRef = umetav1.GetObjectReference(rgn)
	} else {
		rgn, err := s.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: "default"})
		if err != nil {
			return serr.InternalWithErr(err)
		}
		svc.Status.RegionRef = umetav1.GetObjectReference(rgn)
	}

	if svc.Status.ManagedService != nil && svc.Status.ManagedService.Type == "wrdpgw" {
		svc.Status.ManagedService = nil
	}

	return nil
}

func (s *Server) GetService(ctx context.Context, req *metav1.GetOptions) (*corev1.Service, error) {
	if err := apivalidation.CheckGetOptions(req, &apivalidation.CheckGetOptionsOpts{
		ParentsMax: 1,
	}); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: vutils.GetServiceFullNameFromName(req.Name),
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystemHidden(ret); err != nil {
		return nil, err
	}

	return ret, nil
}

var k8sCapabilityRegex = regexp.MustCompile(`^(ALL|[A-Z][A-Z0-9_]{0,29})$`)

func (s *Server) validateHTTPHeader(ctx context.Context, hdrSpec *corev1.Service_Spec_Config_HTTP_Header) error {
	if hdrSpec == nil {
		return nil
	}

	if len(hdrSpec.AddRequestHeaders) > 256 {
		return grpcutils.InvalidArg("Too many addRequestHeaders")
	}

	if len(hdrSpec.AddResponseHeaders) > 256 {
		return grpcutils.InvalidArg("Too many addResponseHeaders")
	}

	if len(hdrSpec.RemoveRequestHeaders) > 256 {
		return grpcutils.InvalidArg("Too many removeRequestHeaders")
	}

	if len(hdrSpec.RemoveResponseHeaders) > 256 {
		return grpcutils.InvalidArg("Too many removeResponseHeaders")
	}

	for _, hdr := range hdrSpec.AddRequestHeaders {
		if !httpguts.ValidHeaderFieldName(hdr.Key) {
			return grpcutils.InvalidArg("invalid header name")
		}

		switch hdr.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
			if !httpguts.ValidHeaderFieldValue(hdr.GetValue()) {
				return grpcutils.InvalidArg("invalid header value")
			}
		case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
			if err := checkCELExpressionString(ctx, hdr.GetEval()); err != nil {
				return grpcutils.InvalidArg("Invalid eval: %s", hdr.GetEval())
			}
		default:
			return grpcutils.InvalidArg("You must provide either a header value or eval")
		}

	}

	for _, hdr := range hdrSpec.AddResponseHeaders {
		if !httpguts.ValidHeaderFieldName(hdr.Key) {
			return grpcutils.InvalidArg("invalid header name")
		}

		switch hdr.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
			if err := s.validateGenStr(hdr.GetValue(), true, "value"); err != nil {
				return err
			}
		case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
			if err := checkCELExpressionString(ctx, hdr.GetEval()); err != nil {
				return grpcutils.InvalidArg("Invalid eval: %s", hdr.GetEval())
			}
		default:
			return grpcutils.InvalidArg("You must provide either a header value or eval")
		}
	}

	for _, hdr := range hdrSpec.RemoveRequestHeaders {
		if err := s.validateGenStr(hdr, true, "key"); err != nil {
			return err
		}
	}

	for _, hdr := range hdrSpec.RemoveResponseHeaders {
		if err := s.validateGenStr(hdr, true, "key"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) validateHTTPAuth(ctx context.Context, authSpec *corev1.Service_Spec_Config_HTTP_Auth) error {
	if authSpec == nil {
		return nil
	}

	if authSpec.GetBearer() != nil {
		if err := s.validateSecretOwner(ctx, authSpec.GetBearer()); err != nil {
			return err
		}
	}

	if authSpec.GetBasic() != nil {
		if authSpec.GetBasic().Username == "" {
			return serr.InvalidArg("Basic Auth username must be set")
		} else {
			if err := apivalidation.ValidateGenASCII(authSpec.GetBasic().Username); err != nil {
				return err
			}
		}

		if err := s.validateSecretOwner(ctx, authSpec.GetBasic().GetPassword()); err != nil {
			return err
		}
	}

	if authSpec.GetCustom() != nil {

		if err := s.validateGenStr(authSpec.GetCustom().Header, true, "header"); err != nil {
			return err
		}

		if err := s.validateSecretOwner(ctx, authSpec.GetCustom().GetValue()); err != nil {
			return err
		}
	}

	if authSpec.GetSigv4() != nil {
		if authSpec.GetSigv4().Service == "" {
			return serr.InvalidArg("sigv4 service must be set")
		} else {
			if err := apivalidation.ValidateGenASCII(authSpec.GetSigv4().Service); err != nil {
				return err
			}
		}

		if authSpec.GetSigv4().Region == "" {
			return serr.InvalidArg("sigv4 region must be set")
		} else {
			if err := apivalidation.ValidateGenASCII(authSpec.GetSigv4().Region); err != nil {
				return err
			}
		}

		if authSpec.GetSigv4().AccessKeyID == "" {
			return serr.InvalidArg("sigv4 accessKeyID be set")
		} else {
			if err := apivalidation.ValidateGenASCII(authSpec.GetSigv4().AccessKeyID); err != nil {
				return err
			}
		}

		if err := s.validateSecretOwner(ctx, authSpec.GetSigv4().GetSecretAccessKey()); err != nil {
			return err
		}
	}

	if authSpec.GetOauth2ClientCredentials() != nil {
		oauth2C := authSpec.GetOauth2ClientCredentials()
		if oauth2C.ClientID == "" {
			return serr.InvalidArg("OAuth2 client ID cannot be empty")
		}
		if oauth2C.TokenURL == "" {
			return serr.InvalidArg("OAuth2 token URL must be set")
		}
		if err := s.validateSecretOwner(ctx, oauth2C.GetClientSecret()); err != nil {
			return err
		}

	}
	return nil
}

func (s *Server) validateHTTPPath(pth *corev1.Service_Spec_Config_HTTP_Path) error {
	if pth == nil {
		return nil
	}

	if pth.AddPrefix != "" {
		if len(pth.AddPrefix) > 512 {
			return grpcutils.InvalidArg("addPrefix is too long: %s", pth.AddPrefix)
		}
		if !govalidator.IsRequestURI(pth.AddPrefix) {
			return grpcutils.InvalidArg("Invalid addPrefix: %s", pth.AddPrefix)
		}
	}

	if pth.RemovePrefix != "" {
		if len(pth.RemovePrefix) > 512 {
			return grpcutils.InvalidArg("removePrefix is too long: %s", pth.RemovePrefix)
		}
		if !govalidator.IsRequestURI(pth.RemovePrefix) {
			return grpcutils.InvalidArg("Invalid removePrefix: %s", pth.RemovePrefix)
		}
	}
	return nil
}

func (s *Server) validatePluginCommon(ctx context.Context, cfgName string,
	names []string, plugin ucorev1.HTTPPlugin) ([]string, error) {
	if err := apivalidation.ValidateName(plugin.GetName(), 0, 0); err != nil {
		return names, err
	}
	if slices.Contains(names, plugin.GetName()) {
		return names, serr.InvalidArg("This Plugin name already exists: %s", cfgName)
	}
	names = append(names, plugin.GetName())

	if err := s.validateCondition(ctx, plugin.GetCondition()); err != nil {
		return names, err
	}

	return names, nil
}

func (s *Server) validatePluginShared(ctx context.Context, plugin ucorev1.HTTPPlugin) (bool, error) {
	switch {
	case plugin.GetLua() != nil:
		return true, s.validatePluginLua(ctx, plugin.GetLua())
	case plugin.GetDirect() != nil:
		return true, s.validatePluginDirect(ctx, plugin.GetDirect())
	case plugin.GetExtProc() != nil:
		return true, s.validatePluginExtProc(ctx, plugin.GetExtProc())
	case plugin.GetJsonSchema() != nil:
		return true, s.validatePluginJSONSchema(ctx, plugin.GetJsonSchema())
	case plugin.GetPath() != nil:
		return true, s.validatePluginPath(ctx, plugin.GetPath())
	case plugin.GetRateLimit() != nil:
		return true, s.validatePluginRateLimit(ctx, plugin.GetRateLimit())
	default:
		return false, nil
	}
}

func (s *Server) validateHTTPPlugins(ctx context.Context, cfgName string,
	plugins []*corev1.Service_Spec_Config_HTTP_Plugin) error {
	if len(plugins) == 0 {
		return nil
	}

	if len(plugins) > maxPlugins {
		return grpcutils.InvalidArg("Too many plugins")
	}

	var names []string
	var err error
	for _, plugin := range plugins {
		if names, err = s.validatePluginCommon(ctx, cfgName, names, plugin); err != nil {
			return err
		}

		isShared, err := s.validatePluginShared(ctx, plugin)
		if err != nil {
			return err
		}
		if isShared {
			continue
		}

		switch {
		case plugin.GetCache() != nil:
			if err := s.validatePluginCache(ctx, plugin.GetCache()); err != nil {
				return err
			}
		default:
			return grpcutils.InvalidArg("plugin type must be set")
		}
	}

	return nil
}

func (s *Server) validatePluginLua(ctx context.Context,
	conf *corev1.Service_Spec_Config_HTTP_Plugin_Lua) error {
	if len(conf.GetInline()) == 0 {
		return serr.InvalidArg("Lua script is empty")
	}

	if len(conf.GetInline()) > 20000 {
		return serr.InvalidArg("Lua script is too large")
	}

	return nil
}

func (s *Server) validatePluginDirect(ctx context.Context,
	conf *corev1.Service_Spec_Config_HTTP_Plugin_Direct) error {
	if conf.StatusCode != 0 {
		if err := apivalidation.ValidateHTTPStatusCode(
			int64(conf.StatusCode)); err != nil {
			return err
		}
	}
	if len(conf.Headers) > 100 {
		return grpcutils.InvalidArg("Too many headers")
	}

	for _, hdr := range conf.Headers {
		if !httpguts.ValidHeaderFieldName(hdr.Key) {
			return grpcutils.InvalidArg("invalid header name")
		}

		if !httpguts.ValidHeaderFieldValue(hdr.Value) {
			return grpcutils.InvalidArg("invalid header value")
		}
	}

	if conf.Body != nil {
		switch conf.Body.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline:
			if len(conf.Body.GetInline()) > 50000 {
				return grpcutils.InvalidArg("inline is too large")
			}
		case *corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_InlineBytes:
			if len(conf.Body.GetInlineBytes()) > 35000 {
				return grpcutils.InvalidArg("inlineBytes is too large")
			}

		}
	}

	return nil
}

func (s *Server) validatePluginExtProc(ctx context.Context,
	conf *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc) error {
	confDuration := umetav1.ToDuration(conf.MessageTimeout).ToGo()
	if confDuration > 6000*time.Millisecond {
		return serr.InvalidArg("message timeout upper limit is exceeded")
	}

	switch conf.Type.(type) {
	case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Address:
		if err := apivalidation.ValidateHostPort(
			conf.GetAddress()); err != nil {
			return err
		}
	case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Container_:
		if conf.GetContainer().Image == "" {
			return grpcutils.InvalidArg("Image address is empty")
		}

		if len(conf.GetContainer().Image) > 256 {
			return grpcutils.InvalidArg("Image address is too long: %s",
				conf.GetContainer().Image)
		}
	}

	return nil
}

func (s *Server) validatePluginCache(ctx context.Context,
	conf *corev1.Service_Spec_Config_HTTP_Plugin_Cache) error {
	if conf.Ttl != nil {
		if err := apivalidation.ValidateDuration(conf.Ttl); err != nil {
			return err
		}
	}
	if conf.Key != nil {
		switch conf.Key.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval:
			if err := checkCELExpressionString(ctx, conf.Key.GetEval()); err != nil {
				return err
			}
		default:
			return grpcutils.InvalidArg("Invalid key type")
		}
	}

	if conf.MaxSize > 256_000_000 {
		return grpcutils.InvalidArg("Invalid maxSize value: %d", conf.MaxSize)
	}

	return nil
}

func (s *Server) validatePluginJSONSchema(ctx context.Context,
	conf *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema) error {
	switch conf.Type.(type) {
	case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline:
		val := conf.GetInline()
		if len(val) == 0 {
			return grpcutils.InvalidArg("jsonSchema is empty")
		}
		if len(val) > 30000 {
			return grpcutils.InvalidArg("jsonSchema is too large")
		}
		if _, err := jsonschemautils.Compile([]byte(val)); err != nil {
			return grpcutils.InvalidArg("invalid jsonSchema")
		}

	default:
		return grpcutils.InvalidArg("Invalid jsonSchema type. Currently it must be set to inline.")
	}

	for _, hdr := range conf.Headers {
		if !httpguts.ValidHeaderFieldName(hdr.Key) {
			return grpcutils.InvalidArg("invalid header name")
		}

		if !httpguts.ValidHeaderFieldValue(hdr.Value) {
			return grpcutils.InvalidArg("invalid header value")
		}
	}

	if conf.Body != nil {
		switch conf.Body.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_Inline:
			if len(conf.Body.GetInline()) > 50000 {
				return grpcutils.InvalidArg("inline is too large")
			}
		case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_InlineBytes:
			if len(conf.Body.GetInlineBytes()) > 35000 {
				return grpcutils.InvalidArg("inlineBytes is too large")
			}

		}
	}

	return nil
}

func (s *Server) validatePluginPath(ctx context.Context,
	pth *corev1.Service_Spec_Config_HTTP_Plugin_Path) error {
	if pth.AddPrefix != "" {
		if len(pth.AddPrefix) > 512 {
			return grpcutils.InvalidArg("addPrefix is too long: %s", pth.AddPrefix)
		}
		if !govalidator.IsRequestURI(pth.AddPrefix) {
			return grpcutils.InvalidArg("Invalid addPrefix: %s", pth.AddPrefix)
		}
	}

	if pth.RemovePrefix != "" {
		if len(pth.RemovePrefix) > 512 {
			return grpcutils.InvalidArg("removePrefix is too long: %s", pth.RemovePrefix)
		}
		if !govalidator.IsRequestURI(pth.RemovePrefix) {
			return grpcutils.InvalidArg("Invalid removePrefix: %s", pth.RemovePrefix)
		}
	}

	return nil
}

func (s *Server) validatePluginRateLimit(ctx context.Context,
	conf *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit) error {
	if conf.Limit == 0 {
		return grpcutils.InvalidArg("Limit must be set")
	} else if conf.Limit < 0 {
		return grpcutils.InvalidArg("Limit cannot be negative: %d", conf.Limit)
	}

	if conf.StatusCode != 0 {
		if err := apivalidation.ValidateHTTPStatusCode(int64(conf.StatusCode)); err != nil {
			return err
		}
	}
	if conf.Window == nil {
		return grpcutils.InvalidArg("Window duration must be set")
	}

	if err := apivalidation.ValidateDuration(conf.Window); err != nil {
		return err
	}

	for _, hdr := range conf.Headers {
		if !httpguts.ValidHeaderFieldName(hdr.Key) {
			return grpcutils.InvalidArg("invalid header name")
		}

		if !httpguts.ValidHeaderFieldValue(hdr.Value) {
			return grpcutils.InvalidArg("invalid header value")
		}
	}

	if conf.Body != nil {
		switch conf.Body.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Body_Inline:
			if len(conf.Body.GetInline()) > 50000 {
				return grpcutils.InvalidArg("inline is too large")
			}
		case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Body_InlineBytes:
			if len(conf.Body.GetInlineBytes()) > 35000 {
				return grpcutils.InvalidArg("inlineBytes is too large")
			}

		}
	}

	return nil
}

func (s *Server) validateHTTPVisibility(visibility *corev1.Service_Spec_Config_HTTP_Visibility) error {
	if visibility == nil {
		return nil
	}

	maxHeaders := 128
	if len(visibility.IncludeRequestHeaders) > maxHeaders {
		return grpcutils.InvalidArg("Too many includeRequestHeader")
	}

	for _, hdr := range visibility.IncludeRequestHeaders {
		if err := s.validateGenStr(hdr, true, "key"); err != nil {
			return err
		}
	}

	if len(visibility.IncludeResponseHeaders) > maxHeaders {
		return grpcutils.InvalidArg("Too many includeResponseHeaders")
	}

	for _, hdr := range visibility.IncludeResponseHeaders {
		if err := s.validateGenStr(hdr, true, "includeResponseHeader"); err != nil {
			return err
		}
	}
	return nil
}

const (
	maxMCPProtocolVersions = 16
	maxMCPEndpointPathLen  = 256

	maxMCPRequestBytesLimit     = 16 * 1024 * 1024
	maxMCPStreamEventBytesLimit = 4 * 1024 * 1024

	maxMCPVisibilityHeaders = 128
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

	if err := s.validateMCPLimits(mcp.GetLimits()); err != nil {
		return err
	}

	if err := s.validateHTTPCors(mcp.GetCors()); err != nil {
		return err
	}

	if err := s.validateMCPVisibility(mcp.GetVisibility()); err != nil {
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

	for _, plugin := range mcp.GetPlugins() {
		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_:
			return grpcutils.InvalidArg(
				"The Cache plugin is unsupported for MCP Services: %s", plugin.Name)
		}
	}

	return nil
}

const (
	maxCorsAllowedOrigins = 64
	maxCorsOriginLen      = 256

	maxLLMModelLen = 256

	maxLLMRequestBytesLimit     = 64 * 1024 * 1024
	maxLLMStreamEventBytesLimit = 4 * 1024 * 1024

	maxLLMVisibilityHeaders = 128

	maxPlugins = 256

	maxPromptContentLen = 256 * 1024

	maxToolFilters       = 128
	maxToolDefinitionLen = 256 * 1024

	maxGuardrailScopes       = 8
	maxGuardrailPatterns     = 128
	maxGuardrailRegexLen     = 2048
	maxGuardrailExcludeRules = 128
)

func (s *Server) validateLLMConfig(ctx context.Context, cfg *corev1.Service_Spec_Config) error {
	llm := cfg.GetLlm()
	if llm == nil {
		return grpcutils.InvalidArg("LLM config is not set")
	}

	if err := s.validateLLMProtocol(llm.GetProtocol()); err != nil {
		return err
	}

	if err := s.validateLLMModel(ctx, llm.GetModel()); err != nil {
		return err
	}

	if err := s.validateLLMLimits(llm.GetLimits()); err != nil {
		return err
	}

	if err := s.validateLLMVisibility(llm.GetVisibility()); err != nil {
		return err
	}

	if err := s.validateHTTPCors(llm.GetCors()); err != nil {
		return err
	}

	if err := s.validateHTTPHeader(ctx, llm.GetHeader()); err != nil {
		return err
	}

	if err := s.validateHTTPAuth(ctx, llm.GetAuth()); err != nil {
		return err
	}

	if err := s.validateHTTPPath(llm.GetPath()); err != nil {
		return err
	}

	if err := s.validateLLMPlugins(ctx, cfg.Name, llm.GetPlugins()); err != nil {
		return err
	}

	return nil
}

func (s *Server) validateLLMPlugins(ctx context.Context, cfgName string,
	plugins []*corev1.Service_Spec_Config_LLM_Plugin) error {
	if len(plugins) == 0 {
		return nil
	}

	if len(plugins) > maxPlugins {
		return grpcutils.InvalidArg("Too many plugins")
	}

	var names []string
	var err error
	for _, plugin := range plugins {
		if names, err = s.validatePluginCommon(ctx, cfgName, names, plugin); err != nil {
			return err
		}

		isShared, err := s.validatePluginShared(ctx, plugin)
		if err != nil {
			return err
		}
		if isShared {
			continue
		}

		switch plugin.GetPhase() {
		case corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH:
			return grpcutils.InvalidArg(
				"The %s Plugin cannot be invoked in the PRE_AUTH phase", plugin.GetName())
		}

		switch {
		case plugin.GetPrompt() != nil:
			if err := s.validatePluginPrompt(ctx, plugin.GetPrompt()); err != nil {
				return err
			}
		case plugin.GetTools() != nil:
			if err := s.validatePluginTools(ctx, plugin.GetTools()); err != nil {
				return err
			}
		case plugin.GetGuardrail() != nil:
			if err := s.validatePluginGuardrail(ctx, plugin.GetGuardrail()); err != nil {
				return err
			}
		default:
			return grpcutils.InvalidArg("plugin type must be set")
		}
	}

	return nil
}

func (s *Server) validatePluginPrompt(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt) error {

	validateContent := func(content *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content,
		isRequired bool) error {
		if content == nil || content.Type == nil {
			if isRequired {
				return grpcutils.InvalidArg("The Prompt content is not set")
			}
			return nil
		}

		switch content.Type.(type) {
		case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Value:
			if content.GetValue() == "" {
				return grpcutils.InvalidArg("The Prompt content value is empty")
			}
			if len(content.GetValue()) > maxPromptContentLen {
				return grpcutils.InvalidArg("The Prompt content value is too large")
			}
		case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Eval:
			if err := checkCELExpressionString(ctx, content.GetEval()); err != nil {
				return err
			}
		case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Opa:
			if err := checkOPAString(ctx, content.GetOpa()); err != nil {
				return err
			}
		default:
			return grpcutils.InvalidArg("Invalid Prompt content type")
		}

		return nil
	}

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_:
		conf := cfg.GetSystem()

		switch conf.GetMode() {
		case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_MODE_UNSET,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_PREPEND,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_APPEND,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REPLACE:
			if err := validateContent(conf.GetContent(), true); err != nil {
				return err
			}
		case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_STRIP:
			if conf.GetContent() != nil {
				return grpcutils.InvalidArg(
					"The STRIP Prompt mode inserts no content, so no content can be set")
			}
		case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REJECT:
			if err := validateContent(conf.GetContent(), false); err != nil {
				return err
			}
		default:
			return grpcutils.InvalidArg("Invalid Prompt system mode")
		}

	case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_:
		conf := cfg.GetMessage()

		switch conf.GetRole() {
		case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_USER,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_ASSISTANT:
		default:
			return grpcutils.InvalidArg("The Prompt message role must be set")
		}

		switch conf.GetPosition() {
		case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_POSITION_UNSET,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_PREPEND,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_APPEND,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_BEFORE,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_AFTER:
		default:
			return grpcutils.InvalidArg("Invalid Prompt message position")
		}

		switch conf.GetSelector() {
		case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_SELECTOR_UNSET,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_LAST,
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_FIRST:
		case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_ALL:
			switch conf.GetPosition() {
			case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_BEFORE,
				corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_AFTER:
				return grpcutils.InvalidArg(
					"The ALL selector cannot be used with a whole new message")
			}
		default:
			return grpcutils.InvalidArg("Invalid Prompt message selector")
		}

		if err := validateContent(conf.GetContent(), true); err != nil {
			return err
		}

	default:
		return grpcutils.InvalidArg("The Prompt type must be set")
	}

	return nil
}

func (s *Server) validatePluginTools(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Tools) error {

	if len(cfg.GetFilters()) > maxToolFilters {
		return grpcutils.InvalidArg("Too many Tools Filters")
	}
	if len(cfg.GetTools()) > maxToolFilters {
		return grpcutils.InvalidArg("Too many Tools")
	}

	for _, filter := range cfg.GetFilters() {
		switch filter.Match.(type) {
		case *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name:
			if err := glob.Validate(filter.GetName()); err != nil {
				return grpcutils.InvalidArgWithErr(err)
			}
		case *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Type:
			if err := glob.Validate(filter.GetType()); err != nil {
				return grpcutils.InvalidArgWithErr(err)
			}
		default:
			return grpcutils.InvalidArg("The Tools Filter match must be set")
		}

		switch filter.GetDecision() {
		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_DECISION_UNSET,
			corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_ALLOW,
			corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE,
			corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_DENY:
			if filter.GetReplace() != nil {
				return grpcutils.InvalidArg(
					"The Tools Filter replace can only be set for the REPLACE Decision")
			}
		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REPLACE:
			if err := validateToolDefinition(ctx, filter.GetReplace()); err != nil {
				return err
			}
		default:
			return grpcutils.InvalidArg("Invalid Tools Filter decision")
		}
	}

	for _, tool := range cfg.GetTools() {
		if err := validateToolDefinition(ctx, tool); err != nil {
			return err
		}

		switch tool.GetPosition() {
		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_POSITION_UNSET,
			corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_PREPEND,
			corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_APPEND:
		default:
			return grpcutils.InvalidArg("Invalid Tools position")
		}
	}

	switch cfg.GetChoice() {
	case corev1.Service_Spec_Config_LLM_Plugin_Tools_CHOICE_UNSET,
		corev1.Service_Spec_Config_LLM_Plugin_Tools_PRESERVE,
		corev1.Service_Spec_Config_LLM_Plugin_Tools_NONE,
		corev1.Service_Spec_Config_LLM_Plugin_Tools_AUTO:
	default:
		return grpcutils.InvalidArg("Invalid Tools choice value")
	}

	if err := s.validateGenStr(cfg.GetDenyMessage(), false, "denyMessage"); err != nil {
		return err
	}

	return nil
}

type toolDefinition interface {
	GetValue() string
	GetEval() string
	GetOpa() string
}

func validateToolDefinition(ctx context.Context, cfg toolDefinition) error {
	if cfg == nil || (cfg.GetValue() == "" && cfg.GetEval() == "" && cfg.GetOpa() == "") {
		return grpcutils.InvalidArg("The tool definition is not set")
	}

	switch {
	case cfg.GetValue() != "":
		if len(cfg.GetValue()) > maxToolDefinitionLen {
			return grpcutils.InvalidArg("The tool definition is too large")
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(cfg.GetValue()), &obj); err != nil {
			return grpcutils.InvalidArg("The tool definition is not a JSON object")
		}
	case cfg.GetEval() != "":
		if err := checkCELExpressionString(ctx, cfg.GetEval()); err != nil {
			return err
		}
	case cfg.GetOpa() != "":
		if err := checkOPAString(ctx, cfg.GetOpa()); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) validatePluginGuardrail(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail) error {

	var isResponse bool
	switch cfg.GetLeg() {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_LEG_UNSET,
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_REQUEST:
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_RESPONSE,
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_BOTH:
		isResponse = true
	default:
		return grpcutils.InvalidArg("Invalid Guardrail leg")
	}

	if len(cfg.GetScopes()) > maxGuardrailScopes {
		return grpcutils.InvalidArg("Too many Guardrail scopes")
	}

	var hasToolDefinitions bool
	for _, scope := range cfg.GetScopes() {
		switch scope {
		case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT,
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_INSTRUCTIONS,
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_TOOL_RESULTS:
		case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_TOOL_DEFINITIONS,
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_ALL:
			hasToolDefinitions = true
		default:
			return grpcutils.InvalidArg("Invalid Guardrail scope")
		}
	}

	if err := s.validateGenStr(cfg.GetDenyMessage(), false, "denyMessage"); err != nil {
		return err
	}

	if len(cfg.GetPatterns()) == 0 {
		return grpcutils.InvalidArg("The Guardrail Patterns are empty")
	}
	if len(cfg.GetPatterns()) > maxGuardrailPatterns {
		return grpcutils.InvalidArg("Too many Guardrail Patterns")
	}

	for _, pattern := range cfg.GetPatterns() {
		if err := s.validateGuardrailPattern(ctx, pattern,
			isResponse, hasToolDefinitions); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) validateGuardrailPattern(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern,
	isResponse, hasToolDefinitions bool) error {

	switch cfg.Match.(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex:
		if cfg.GetRegex() == "" {
			return grpcutils.InvalidArg("The Guardrail Pattern regex is empty")
		}
		if len(cfg.GetRegex()) > maxGuardrailRegexLen {
			return grpcutils.InvalidArg("The Guardrail Pattern regex is too long")
		}
		if _, err := regexp.Compile(cfg.GetRegex()); err != nil {
			return grpcutils.InvalidArg("Could not compile the Guardrail Pattern regex")
		}
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type_:
		if cfg.GetType() ==
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_TYPE_UNSET {
			return grpcutils.InvalidArg("The Guardrail Pattern type must be set")
		}
		if _, ok := corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type_name[int32(cfg.GetType())]; !ok {
			return grpcutils.InvalidArg("Invalid Guardrail Pattern type")
		}
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets_:
		excludeRules := cfg.GetSecrets().GetExcludeRules()
		if len(excludeRules) > maxGuardrailExcludeRules {
			return grpcutils.InvalidArg("Too many Guardrail Pattern excludeRules")
		}
		for _, excludeRule := range excludeRules {
			if err := s.validateGenStr(excludeRule, true, "excludeRules"); err != nil {
				return err
			}
		}
	default:
		return grpcutils.InvalidArg("The Guardrail Pattern match must be set")
	}

	var isRewrite bool
	switch cfg.GetAction() {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_ACTION_UNSET,
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY:
		if cfg.GetReplace() != nil {
			return grpcutils.InvalidArg(
				"The Guardrail Pattern replace can only be set for the REPLACE Action")
		}
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT,
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP:
		isRewrite = true
		if cfg.GetReplace() != nil {
			return grpcutils.InvalidArg(
				"The Guardrail Pattern replace can only be set for the REPLACE Action")
		}
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE:
		isRewrite = true
		if err := s.validateGuardrailReplace(ctx, cfg.GetReplace()); err != nil {
			return err
		}
	default:
		return grpcutils.InvalidArg("Invalid Guardrail Pattern action")
	}

	if isRewrite {
		if isResponse {
			return grpcutils.InvalidArg(
				"A Guardrail that inspects the response can only use the DENY Action")
		}
		if hasToolDefinitions {
			return grpcutils.InvalidArg(
				"A Guardrail that inspects the tool definitions can only use the DENY Action")
		}
	}

	return nil
}

func (s *Server) validateGuardrailReplace(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace) error {
	if cfg == nil || cfg.Type == nil {
		return grpcutils.InvalidArg("The Guardrail Pattern replace is not set")
	}

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Value:
		if err := s.validateGenStr(cfg.GetValue(), false, "value"); err != nil {
			return err
		}
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Eval:
		if err := checkCELExpressionString(ctx, cfg.GetEval()); err != nil {
			return err
		}
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Opa:
		if err := checkOPAString(ctx, cfg.GetOpa()); err != nil {
			return err
		}
	default:
		return grpcutils.InvalidArg("Invalid Guardrail Pattern replace type")
	}

	return nil
}

func (s *Server) validateLLMProtocol(protocol corev1.Service_Spec_Config_LLM_Protocol) error {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_PROTOCOL_UNSET,
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return nil
	default:
		return grpcutils.InvalidArg("Unsupported LLM protocol")
	}
}

func (s *Server) validateLLMModel(ctx context.Context,
	model *corev1.Service_Spec_Config_LLM_Model) error {
	if model == nil {
		return nil
	}

	switch model.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Model_Value:
		if model.GetValue() == "" {
			return grpcutils.InvalidArg("The LLM model value cannot be empty")
		}
		if len(model.GetValue()) > maxLLMModelLen {
			return grpcutils.InvalidArg("The LLM model value is too long")
		}
		for i := 0; i < len(model.GetValue()); i++ {
			if model.GetValue()[i] < 0x20 || model.GetValue()[i] == 0x7f {
				return grpcutils.InvalidArg(
					"The LLM model value contains an invalid control character")
			}
		}
	case *corev1.Service_Spec_Config_LLM_Model_Eval:
		if err := checkCELExpressionString(ctx, model.GetEval()); err != nil {
			return grpcutils.InvalidArg("Invalid eval: %s", model.GetEval())
		}
	}

	return nil
}

func (s *Server) validateLLMLimits(limits *corev1.Service_Spec_Config_LLM_Limits) error {
	if limits == nil {
		return nil
	}

	if limits.MaxRequestBytes > maxLLMRequestBytesLimit {
		return grpcutils.InvalidArg("maxRequestBytes is above the maximum allowed value")
	}

	if limits.MaxStreamEventBytes > maxLLMStreamEventBytesLimit {
		return grpcutils.InvalidArg("maxStreamEventBytes is above the maximum allowed value")
	}

	return nil
}

func (s *Server) validateLLMVisibility(visibility *corev1.Service_Spec_Config_LLM_Visibility) error {
	if visibility == nil {
		return nil
	}

	for _, hdrs := range [][]string{
		visibility.IncludeRequestHeaders,
		visibility.IncludeResponseHeaders,
		visibility.ExcludeRequestHeaders,
		visibility.ExcludeResponseHeaders,
	} {
		if len(hdrs) > maxLLMVisibilityHeaders {
			return grpcutils.InvalidArg("Too many LLM visibility headers")
		}
		for _, hdr := range hdrs {
			if err := s.validateGenStr(hdr, true, "key"); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Server) validateMCPEndpoint(path string) error {
	if path == "" {
		return nil
	}

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

func (s *Server) validateMCPLimits(limits *corev1.Service_Spec_Config_MCP_Limits) error {
	if limits == nil {
		return nil
	}

	if limits.MaxRequestBytes > maxMCPRequestBytesLimit {
		return grpcutils.InvalidArg("maxRequestBytes is above the maximum allowed value")
	}

	if limits.MaxStreamEventBytes > maxMCPStreamEventBytesLimit {
		return grpcutils.InvalidArg("maxStreamEventBytes is above the maximum allowed value")
	}

	return nil
}

func (s *Server) validateHTTPCors(cors *corev1.Service_Spec_Config_HTTP_CORS) error {
	if cors == nil {
		return nil
	}

	if len(cors.AllowOriginStringMatch) > maxCorsAllowedOrigins {
		return grpcutils.InvalidArg("Too many allowed CORS origins")
	}

	var seen []string
	for _, arg := range cors.AllowOriginStringMatch {
		if arg == "*" {
			if slices.Contains(seen, arg) {
				return grpcutils.InvalidArg("Duplicate allowed CORS origin: %s", arg)
			}
			seen = append(seen, arg)
			continue
		}

		if len(arg) > maxCorsOriginLen {
			return grpcutils.InvalidArg("The allowed CORS origin is too long")
		}

		u, err := url.Parse(arg)
		if err != nil || u.Scheme == "" || u.Host == "" ||
			u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return grpcutils.InvalidArg(
				`The allowed CORS origin must be either "*" or in the "scheme://host[:port]" format: %s`, arg)
		}

		if slices.Contains(seen, arg) {
			return grpcutils.InvalidArg("Duplicate allowed CORS origin: %s", arg)
		}
		seen = append(seen, arg)
	}

	return nil
}

func (s *Server) validateMCPVisibility(visibility *corev1.Service_Spec_Config_MCP_Visibility) error {
	if visibility == nil {
		return nil
	}

	for _, hdrs := range [][]string{
		visibility.IncludeRequestHeaders,
		visibility.IncludeResponseHeaders,
		visibility.ExcludeRequestHeaders,
		visibility.ExcludeResponseHeaders,
	} {
		if len(hdrs) > maxMCPVisibilityHeaders {
			return grpcutils.InvalidArg("Too many MCP visibility headers")
		}
		for _, hdr := range hdrs {
			if err := s.validateGenStr(hdr, true, "key"); err != nil {
				return err
			}
		}
	}

	return nil
}
