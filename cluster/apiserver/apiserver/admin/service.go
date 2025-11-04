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
	"fmt"
	"mime"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/kaptinlin/jsonschema"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/rscutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/utilnet"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/ldflags"
)

func (s *Server) ListService(ctx context.Context, req *corev1.ListServiceOptions) (*corev1.ServiceList, error) {

	var err error

	var listOpts []*rmetav1.ListOptions_Filter

	if req.NamespaceRef != nil {
		if err := apivalidation.CheckObjectRef(req.NamespaceRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}
		ns, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{
			Uid:  req.NamespaceRef.Uid,
			Name: req.NamespaceRef.Name,
		})
		if err != nil {
			return nil, err
		}
		listOpts = append(listOpts, urscsrv.FilterFieldEQValStr("status.namespaceRef.uid", ns.Metadata.Uid))
	}

	if req.RegionRef != nil {
		if err := apivalidation.CheckObjectRef(req.RegionRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}
		rgn, err := s.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Uid:  req.RegionRef.Uid,
			Name: req.RegionRef.Name,
		})
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

	if err := s.validateService(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	nsName, err := getNamespace(req.Metadata.Name)
	if err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: nsName})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	item, err := s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Name: vutils.GetServiceFullNameFromName(req.Metadata.Name),
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	common.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec

	if err := s.checkAndSetService(ctx, item); err != nil {
		return nil, err
	}

	item, err = s.octeliumC.CoreC().UpdateService(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) DoCreateService(ctx context.Context, req *corev1.Service, isSystemService bool) (*corev1.Service, error) {
	if err := s.validateService(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
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

	if err := s.checkAndSetService(ctx, item); err != nil {
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

	_, err = s.octeliumC.CoreC().DeleteService(ctx, &rmetav1.DeleteOptions{Uid: svc.Metadata.Uid})
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return ret, nil
}

func (s *Server) checkAndSetService(ctx context.Context,
	svc *corev1.Service) error {

	octeliumC := s.octeliumC

	svc.Metadata.SpecLabels = make(map[string]string)
	spec := svc.Spec
	specLabels := svc.Metadata.SpecLabels

	switch svc.Spec.Mode {
	case corev1.Service_Spec_MODE_UNSET:
		return grpcutils.InvalidArg("Service mode must be set")
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

	if spec.Config != nil && spec.Config.GetUpstream() != nil {
		if spec.Config.GetUpstream().User != "" {
			usr, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: spec.Config.GetUpstream().User})
			if err != nil {
				if grpcerr.IsNotFound(err) {
					return serr.InvalidArg("The upstream User %s does not exist", spec.Config.GetUpstream().User)
				}
				return serr.InternalWithErr(err)
			}

			specLabels[fmt.Sprintf("host-user-%s", usr.Metadata.Name)] = usr.Metadata.Uid
		}

		switch spec.Config.GetUpstream().Type.(type) {
		case *corev1.Service_Spec_Config_Upstream_Url:

		case *corev1.Service_Spec_Config_Upstream_Loadbalance_:

			eps := spec.Config.GetUpstream().GetLoadbalance().Endpoints

			if len(eps) == 0 {
				return grpcutils.InvalidArg("There must be at least 1 endpoint in loadBalance")
			}

			if len(eps) > 100 {
				return grpcutils.InvalidArg("Too many endpoints: %d in loadBalance", len(eps))
			}

			for _, ep := range eps {

				if ep.User != "" {
					usr, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: ep.User})
					if err != nil {
						if grpcerr.IsNotFound(err) {
							return serr.InvalidArg("The upstream User %s does not exist", ep.User)
						}
						return serr.InternalWithErr(err)
					}

					specLabels[fmt.Sprintf("host-user-%s", usr.Metadata.Name)] = usr.Metadata.Uid
				}

			}

		case *corev1.Service_Spec_Config_Upstream_Container_:

			typ := spec.Config.GetUpstream().GetContainer()

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
					if err := apivalidation.ValidateEnvVarKey(itm.GetValue()); err != nil {
						return err
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
	}

	if spec.Authorization != nil {

		for _, inlinePolicy := range spec.Authorization.InlinePolicies {
			if err := s.validatePolicySpec(ctx, inlinePolicy.Spec); err != nil {
				return err
			}
		}

		for _, p := range spec.Authorization.Policies {
			_, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
				Name: p,
			})
			if grpcerr.IsNotFound(err) {
				return grpcutils.InvalidArg("The Policy %s is not found", p)
			}
		}
	}

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

	validateConfig := func(cfg *corev1.Service_Spec_Config) error {
		if cfg == nil {
			return grpcutils.InvalidArg("Config is not set")
		}

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
						return grpcutils.InvalidArg("Invalid trusted CA PEM: %s", ca)
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
						return grpcutils.InvalidArg("Invalid trusted CA PEM: %s", ca)
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

			if cfg.GetHttp().Header != nil {
				hdrSpec := cfg.GetHttp().Header

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
					if err := s.validateGenStr(hdr.Key, true, "key"); err != nil {
						return err
					}

					switch hdr.Type.(type) {
					case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
						if err := s.validateGenStr(hdr.GetValue(), true, "value"); err != nil {
							return err
						}
					case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
						if err := checkCELExpression(ctx, hdr.GetEval()); err != nil {
							return grpcutils.InvalidArg("Invalid eval: %s", hdr.GetEval())
						}
					default:
						return grpcutils.InvalidArg("You must provide either a header value or eval")
					}

				}

				for _, hdr := range hdrSpec.AddResponseHeaders {
					if err := s.validateGenStr(hdr.Key, true, "key"); err != nil {
						return err
					}

					switch hdr.Type.(type) {
					case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
						if err := s.validateGenStr(hdr.GetValue(), true, "value"); err != nil {
							return err
						}
					case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
						if err := checkCELExpression(ctx, hdr.GetEval()); err != nil {
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
			}

			if cfg.GetHttp().Auth != nil {
				authSpec := cfg.GetHttp().Auth

				if authSpec.GetBearer() != nil {
					if authSpec.GetBearer().GetFromSecret() != "" {
						_, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
							Name: authSpec.GetBearer().GetFromSecret()})
						if err != nil {
							if !grpcerr.IsInternal(err) {
								return serr.InvalidArg("Bearer Secret: %s does not exist",
									authSpec.GetBearer().GetFromSecret())
							}
							return serr.InternalWithErr(err)
						}

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
							if _, err := jsonschema.NewCompiler().Compile([]byte(val)); err != nil {
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

			if cfg.GetHttp().Path != nil {
				pth := cfg.GetHttp().Path
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

			if len(cfg.GetHttp().Plugins) > 0 {
				if len(cfg.GetHttp().Plugins) > 256 {
					return grpcutils.InvalidArg("Too many plugins")
				}

				var names []string
				for _, plugin := range cfg.GetHttp().Plugins {

					if err := apivalidation.ValidateName(plugin.Name, 0, 0); err != nil {
						return err
					}
					if slices.Contains(names, plugin.Name) {
						return serr.InvalidArg("This Plugin name already exists: %s", cfg.Name)
					}
					names = append(names, plugin.Name)

					if err := s.validateCondition(ctx, plugin.Condition); err != nil {
						return err
					}

					switch plugin.Type.(type) {
					case *corev1.Service_Spec_Config_HTTP_Plugin_Lua_:
						if len(plugin.GetLua().GetInline()) == 0 {
							return serr.InvalidArg("Lua script is empty")
						}

						if len(plugin.GetLua().GetInline()) > 20000 {
							return serr.InvalidArg("Lua script is too large")
						}
					case *corev1.Service_Spec_Config_HTTP_Plugin_Direct_:
						if plugin.GetDirect().StatusCode != 0 {
							if err := apivalidation.ValidateHTTPStatusCode(
								int64(plugin.GetDirect().StatusCode)); err != nil {
								return err
							}
						}
						if len(plugin.GetDirect().Headers) > 100 {
							return grpcutils.InvalidArg("Too many headers")
						}

						for k, v := range plugin.GetDirect().Headers {
							if err := s.validateGenStr(k, true, "key"); err != nil {
								return err
							}

							if err := s.validateGenStr(v, true, "value"); err != nil {
								return err
							}
						}

						if plugin.GetDirect().Body != nil {
							switch plugin.GetDirect().Body.Type.(type) {
							case *corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline:
								if len(plugin.GetDirect().Body.GetInline()) > 50000 {
									return grpcutils.InvalidArg("inline is too large")
								}
							case *corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_InlineBytes:
								if len(plugin.GetDirect().Body.GetInlineBytes()) > 35000 {
									return grpcutils.InvalidArg("inlineBytes is too large")
								}

							}
						}

					case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_:

						confDuration := umetav1.ToDuration(plugin.GetExtProc().MessageTimeout).ToGo()
						if confDuration > 6000*time.Millisecond {
							return serr.InvalidArg("message timeout upper limit is exceeded")
						}

						switch plugin.GetExtProc().Type.(type) {
						case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Address:
							if err := apivalidation.ValidateHostPort(
								plugin.GetExtProc().GetAddress()); err != nil {
								return err
							}
						case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Container_:
							if plugin.GetExtProc().GetContainer().Image == "" {
								return grpcutils.InvalidArg("Image address is empty")
							}

							if len(plugin.GetExtProc().GetContainer().Image) > 256 {
								return grpcutils.InvalidArg("Image address is too long: %s",
									plugin.GetExtProc().GetContainer().Image)
							}
						}
					case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_:
						conf := plugin.GetCache()
						if conf.Ttl != nil {
							if err := apivalidation.ValidateDuration(conf.Ttl); err != nil {
								return err
							}
						}
						if conf.Key != nil {
							switch conf.Key.Type.(type) {
							case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval:
								if err := checkCELExpression(ctx, conf.Key.GetEval()); err != nil {
									return err
								}
							default:
								return grpcutils.InvalidArg("Invalid key type")
							}
						}

						if conf.MaxSize > 256_000_000 {
							return grpcutils.InvalidArg("Invalid maxSize value: %d", conf.MaxSize)
						}

					case *corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema:
						conf := plugin.GetJsonSchema()
						switch conf.Type.(type) {
						case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline:
							val := conf.GetInline()
							if len(val) == 0 {
								return grpcutils.InvalidArg("jsonSchema is empty")
							}
							if len(val) > 30000 {
								return grpcutils.InvalidArg("jsonSchema is too large")
							}
							if _, err := jsonschema.NewCompiler().Compile([]byte(val)); err != nil {
								return grpcutils.InvalidArg("invalid jsonSchema")
							}

						default:
							return grpcutils.InvalidArg("Invalid jsonSchema type. Currently it must be set to inline.")
						}

						for k, v := range conf.Headers {
							if err := s.validateGenStr(k, true, "key"); err != nil {
								return err
							}

							if err := s.validateGenStr(v, true, "value"); err != nil {
								return err
							}
						}

						if conf.Body != nil {
							switch conf.Body.Type.(type) {
							case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_Inline:
								if len(conf.GetInline()) > 50000 {
									return grpcutils.InvalidArg("inline is too large")
								}
							case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_InlineBytes:
								if len(conf.Body.GetInlineBytes()) > 35000 {
									return grpcutils.InvalidArg("inlineBytes is too large")
								}

							}
						}

					case *corev1.Service_Spec_Config_HTTP_Plugin_Path_:

						pth := plugin.GetPath()
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

					case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_:

						conf := plugin.GetRateLimit()
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

						for k, v := range conf.Headers {
							if err := s.validateGenStr(k, true, "key"); err != nil {
								return err
							}

							if err := s.validateGenStr(v, true, "value"); err != nil {
								return err
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

					default:
						return grpcutils.InvalidArg("plugin type must be set")
					}
				}
			}

			if cfg.GetHttp().Visibility != nil {
				visibility := cfg.GetHttp().Visibility
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
			}

		case *corev1.Service_Spec_Config_Kubernetes_:
			if spec.Mode != corev1.Service_Spec_KUBERNETES {
				return grpcutils.InvalidArg("KUBERNETES mode must be set for KUBERNETES config to be used")
			}

			k8s := spec.GetConfig().GetKubernetes()

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
				} else {
					specLabels[fmt.Sprintf("k8s-kubeconfig-url-%s", ucorev1.ToServiceConfig(cfg).GetRealName())] = clstr.Cluster.Server
				}

				if usr := kubeconfig.GetUser(k8s.GetKubeconfig().Context); usr == nil {
					return serr.InvalidArg("No User found in the Kubeconfig")
				} else {
					if usr.User.Token != "" {
						specLabels[fmt.Sprintf("k8s-kubeconfig-has-token-%s", ucorev1.ToServiceConfig(cfg).GetRealName())] = "true"
					}

				}

			case *corev1.Service_Spec_Config_Kubernetes_ClientCertificate:
				if k8s.GetClientCertificate() == nil ||
					k8s.GetClientCertificate().GetFromSecret() == "" {
					return serr.InvalidArg("Client certificate key secret must be supplied")
				}

				_, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
					Name: k8s.GetClientCertificate().GetFromSecret()})
				if err != nil {
					if grpcerr.IsNotFound(err) {
						return serr.InvalidArg("The Secret %s does not exist", k8s.GetKubeconfig().GetFromSecret())
					}
					return serr.InternalWithErr(err)
				}
			case *corev1.Service_Spec_Config_Kubernetes_BearerToken_:

				if err := s.validateSecretOwner(ctx, k8s.GetBearerToken()); err != nil {
					return err
				}

			default:
				return serr.InvalidArg("Unsupported kubernetes config type")
			}

		case *corev1.Service_Spec_Config_Ssh:
			if spec.Mode != corev1.Service_Spec_SSH {
				return grpcutils.InvalidArg("SSH mode must be set for SSH config to be used")
			}
			inSSH := cfg.GetSsh()

			if inSSH.Auth != nil {
				switch inSSH.Auth.Type.(type) {
				case *corev1.Service_Spec_Config_SSH_Auth_Password_:

					switch inSSH.Auth.GetPassword().Type.(type) {
					case *corev1.Service_Spec_Config_SSH_Auth_Password_FromSecret:

						_, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: inSSH.Auth.GetPassword().GetFromSecret()})
						if err != nil {
							if !grpcerr.IsInternal(err) {
								return serr.InvalidArg("SSH password Secret: %s does not exist", inSSH.Auth.GetPassword().GetFromSecret())
							}
							return serr.InternalWithErr(err)
						}

					}

				case *corev1.Service_Spec_Config_SSH_Auth_PrivateKey_:

					switch inSSH.Auth.GetPrivateKey().Type.(type) {
					case *corev1.Service_Spec_Config_SSH_Auth_PrivateKey_FromSecret:

						_, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: inSSH.Auth.GetPrivateKey().GetFromSecret()})
						if err != nil {
							if !grpcerr.IsInternal(err) {
								return serr.InvalidArg("SSH private key Secret: %s does not exist", inSSH.Auth.GetPrivateKey().GetFromSecret())
							}
							return serr.InternalWithErr(err)
						}

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

		return nil
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

		if err := validateConfig(spec.Config); err != nil {
			return err
		}
	}

	if spec.DynamicConfig != nil {

		if len(spec.DynamicConfig.Configs) > 256 {
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

			if err := validateConfig(cfg); err != nil {
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
				if err := checkCELExpression(ctx, rule.GetEval()); err != nil {
					return grpcutils.InvalidArg("Invalid eval: %s", rule.GetEval())
				}
			default:
				return grpcutils.InvalidArg("You must provide either a config name or eval")
			}

		}
	}

	if svc.Spec.IsPublic && !ucorev1.ToService(svc).IsHTTP() {
		return serr.InvalidArg("The Service: %s is not an HTTP-based Service to be exposed publicly.", svc.Metadata.Name)
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
			return (svc.Spec.Port)
		}

		l := ucorev1.ToService(svc)

		if l.IsESSH() {
			return 22
		}

		if l.IsManagedService() {
			return 8080
		}

		upstreamPort := l.UpstreamRealPort()

		if !l.Spec.IsTLS && l.IsHTTP() && upstreamPort == 443 {
			return 80
		}

		return uint32(upstreamPort)
	}()

	if !ldflags.IsTest() {
		reservedPorts := []uint32{
			uint32(vutils.HealthCheckPortVigil),
			uint32(vutils.HealthCheckPortManagedService),
		}

		if slices.Contains(reservedPorts, svc.Status.Port) {
			return grpcutils.InvalidArg("This Service port number is reserved by the Cluster: %d", svc.Status.Port)
		}
	}

	if !ucorev1.ToService(svc).IsManagedService() {
		if svc.Spec.Config == nil &&
			(svc.Spec.DynamicConfig == nil || len(svc.Spec.DynamicConfig.Configs) == 0) {
			return grpcutils.InvalidArg("There must be at least a Config or a named dynamic Config")
		}
	}

	/*
		if svc.Spec.Config == nil || svc.Spec.Config.Upstream == nil {
			switch {
			case ucorev1.ToService(svc).IsESSH(),
				ucorev1.ToService(svc).IsManagedService(),
				ucorev1.ToService(svc).IsKubernetes() && svc.Spec.Config.GetKubernetes().GetKubeconfig() != nil:
			default:
				return grpcutils.InvalidArg("An upstream (e.g. a URL) must be set")
			}
		}
	*/

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

func (s *Server) validateService(ctx context.Context, itm *corev1.Service) error {

	if err := apivalidation.ValidateCommon(itm, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
			ParentsMax:  1,
		},
	}); err != nil {
		return err
	}

	if itm.Spec == nil {
		return grpcutils.InvalidArg("You must provide spec")
	}

	spec := itm.Spec

	if err := apivalidation.ValidateAttrs(spec.Attrs); err != nil {
		return err
	}

	backendPorts := []int{}
	backendSchemes := []string{}

	checkURL := func(u string) error {
		if u == "" {
			return grpcutils.InvalidArg("You must provide backend URL")
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

	if spec.Config != nil && spec.Config.GetUpstream() != nil {
		switch spec.Config.GetUpstream().Type.(type) {
		case *corev1.Service_Spec_Config_Upstream_Url:
			if err := checkURL(spec.Config.GetUpstream().GetUrl()); err != nil {
				return err
			}
		case *corev1.Service_Spec_Config_Upstream_Loadbalance_:
			if len(spec.Config.GetUpstream().GetLoadbalance().Endpoints) == 0 {
				return grpcutils.InvalidArg("There must be at least one endpoint in the upstream")
			}

			for _, b := range spec.Config.GetUpstream().GetLoadbalance().Endpoints {
				if err := checkURL(b.Url); err != nil {
					return err
				}
			}
		case *corev1.Service_Spec_Config_Upstream_Container_:
			if err := apivalidation.ValidatePort(int(spec.Config.GetUpstream().GetContainer().Port)); err != nil {
				return err
			}

		}
	}

	if spec.Port != 0 {
		if err := apivalidation.ValidatePort(int(spec.Port)); err != nil {
			return err
		}
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

	if err := s.validatePolicyOwner(ctx, itm.Spec.Authorization); err != nil {
		return err
	}

	if itm.Spec.IsAnonymous {
		if !itm.Spec.IsPublic {
			return grpcutils.InvalidArg("Anonymous access mode requires isPublic to be enabled")
		}
		switch itm.Spec.Mode {
		case corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB, corev1.Service_Spec_GRPC:
		default:
			return grpcutils.InvalidArg("Anonymous access mode requires HTTP or WEB modes")
		}
		if itm.Spec.Authorization != nil {
			return grpcutils.InvalidArg("Anonymous access mode requires no authorization configuration")
		}
	}

	return nil
}
