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

package genesis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	corev1k8s "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const targetClusterUID = "octelium.com/genesis-cluster-uid"
const targetDomain = "octelium.com/genesis-domain"
const targetRegionUID = "octelium.com/genesis-region-uid"
const targetRegionName = "octelium.com/genesis-region-name"
const targetNamespaceUID = "octelium.com/genesis-namespace-uid"
const targetStorageHash = "octelium.com/genesis-storage-target"

func sameDomain(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func checkTargetDomain(requested, actual string) error {
	if actual == "" || (requested != "" && !sameDomain(requested, actual)) {
		return errors.Errorf("The requested domain %q does not match the Cluster domain %q", requested, actual)
	}
	return nil
}

func checkTargetAnnotations(actual, expected map[string]string) error {
	bound := false
	for _, key := range []string{targetClusterUID, targetDomain, targetRegionUID, targetRegionName, targetNamespaceUID} {
		_, ok := actual[key]
		bound = bound || ok
	}
	if !bound {
		return nil
	}
	for _, key := range []string{targetClusterUID, targetDomain, targetRegionUID, targetRegionName, targetNamespaceUID} {
		value := actual[key]
		matches := value != "" && value == expected[key]
		if key == targetDomain {
			matches = value != "" && sameDomain(value, expected[key])
		}
		if !matches {
			return errors.Errorf("The Kubernetes installation identity %s does not match the target Cluster/Region", key)
		}
	}
	return nil
}

func (g *Genesis) validateUpgradeTarget(ctx context.Context, input *LoadedClusterResource, cc *corev1.ClusterConfig, region *corev1.Region) error {
	if cc.GetMetadata().GetUid() == "" || region.GetMetadata().GetUid() == "" {
		return errors.Errorf("The target Cluster/Region has no resource identity")
	}
	if err := checkTargetDomain(os.Getenv("OCTELIUM_DOMAIN"), cc.GetStatus().GetDomain()); err != nil {
		return err
	}
	if err := checkTargetDomain(input.Domain, cc.Status.Domain); err != nil {
		return err
	}
	name := input.Region.GetMetadata().GetName()
	if name == "" {
		name = "default"
	}
	if region.Metadata.Name != name || (input.Region.GetMetadata().GetUid() != "" && input.Region.Metadata.Uid != region.Metadata.Uid) {
		return errors.Errorf("The bootstrap Region does not match the target Region")
	}
	if requested := os.Getenv("OCTELIUM_REGION_NAME"); requested != "" && requested != "default" && requested != name {
		return errors.Errorf("The requested Region %q does not match the bootstrap Region %q", requested, name)
	}
	state, err := g.getK8sSecret(ctx, vutils.K8sNS, initializationSecretName)
	if err == nil {
		id, owner := string(state.Data["id"]), cc.Metadata.Annotations[initializationIDKey]
		if id == "" || (owner != "" && owner != id) {
			return errors.Errorf("The primary storage belongs to another Cluster initialization")
		}
		if err := g.validateInitializationNamespace(ctx, state); err != nil {
			return err
		}
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	return g.reconcileInstallationTarget(ctx, cc, region, false)
}

func (g *Genesis) validateInitializationNamespace(ctx context.Context, state *corev1k8s.Secret) error {
	uid, ok := state.Data["namespace-uid"]
	if !ok {
		return nil
	}
	namespace, err := k8sretry.Read(ctx, func(ctx context.Context) (*corev1k8s.Namespace, error) {
		return g.k8sC.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, metav1.GetOptions{})
	})
	if err != nil {
		return err
	}
	if len(uid) == 0 || string(namespace.UID) != string(uid) || namespace.DeletionTimestamp != nil {
		return errors.Errorf("The initialization checkpoint belongs to another Kubernetes namespace")
	}
	return nil
}

func storageTargetHash(secret *corev1k8s.Secret) string {
	data := map[string]string{"host": strings.ToLower(strings.TrimSuffix(string(secret.Data["host"]), ".")), "port": string(secret.Data["port"]), "database": string(secret.Data["database"])}
	if secret.Name == "octelium-postgres" {
		if data["port"] == "" || data["port"] == "0" {
			data["port"] = "5432"
		}
		if data["database"] == "" {
			data["database"] = string(secret.Data["username"])
			if data["database"] == "" {
				data["database"] = "postgres"
			}
		}
	} else {
		if data["port"] == "" || data["port"] == "0" {
			data["port"] = "6379"
		}
		if data["database"] == "" {
			data["database"] = "0"
		}
	}
	encoded, _ := json.Marshal(data)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (g *Genesis) reconcileInstallationTarget(ctx context.Context, cc *corev1.ClusterConfig, region *corev1.Region, save bool) error {
	namespace, err := k8sretry.Read(ctx, func(ctx context.Context) (*corev1k8s.Namespace, error) {
		return g.k8sC.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, metav1.GetOptions{})
	})
	if err != nil {
		return err
	}
	if namespace.UID == "" || namespace.DeletionTimestamp != nil {
		return errors.Errorf("The target Kubernetes namespace has no live identity")
	}
	expected := map[string]string{
		targetClusterUID: cc.GetMetadata().GetUid(), targetDomain: cc.GetStatus().GetDomain(),
		targetRegionUID: region.GetMetadata().GetUid(), targetRegionName: region.GetMetadata().GetName(), targetNamespaceUID: string(namespace.UID),
	}
	for _, value := range expected {
		if value == "" {
			return errors.Errorf("The target Cluster/Region identity is incomplete")
		}
	}
	for key, env := range map[string]string{
		targetClusterUID: "OCTELIUM_GENESIS_CLUSTER_UID", targetRegionUID: "OCTELIUM_GENESIS_REGION_UID", targetNamespaceUID: "OCTELIUM_GENESIS_NAMESPACE_UID",
	} {
		if value := os.Getenv(env); value != "" && value != expected[key] {
			return errors.Errorf("The submitted genesis identity %s does not match the target Cluster/Region", key)
		}
	}
	cm, err := g.getK8sConfigMap(ctx, vutils.K8sNS, installationConfigMapName)
	if err == nil {
		if err := checkTargetAnnotations(cm.Annotations, expected); err != nil {
			return err
		}
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	for _, name := range []string{"octelium-postgres", "octelium-redis"} {
		secret, err := g.getK8sSecret(ctx, vutils.K8sNS, name)
		if k8serr.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err := checkTargetAnnotations(secret.Annotations, expected); err != nil {
			return err
		}
		if hash, ok := secret.Annotations[targetStorageHash]; ok && hash != storageTargetHash(secret) {
			return errors.Errorf("The %s storage target changed after installation", name)
		}
	}
	if !save {
		return nil
	}
	for _, name := range []string{"octelium-postgres", "octelium-redis"} {
		if err := k8sretry.Do(ctx, func(ctx context.Context) error {
			secret, err := g.getK8sSecret(ctx, vutils.K8sNS, name)
			if k8serr.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if err := checkTargetAnnotations(secret.Annotations, expected); err != nil {
				return err
			}
			hash := storageTargetHash(secret)
			if prior, ok := secret.Annotations[targetStorageHash]; ok && prior != hash {
				return errors.Errorf("The %s storage target changed after installation", name)
			}
			if secret.Annotations[targetClusterUID] == expected[targetClusterUID] && secret.Annotations[targetStorageHash] == hash {
				return nil
			}
			secret = secret.DeepCopy()
			if secret.Annotations == nil {
				secret.Annotations = make(map[string]string)
			}
			for key, value := range expected {
				secret.Annotations[key] = value
			}
			secret.Annotations[targetStorageHash] = hash
			_, err = g.k8sC.CoreV1().Secrets(vutils.K8sNS).Update(ctx, secret, metav1.UpdateOptions{})
			return err
		}); err != nil {
			return err
		}
	}
	return k8sretry.Do(ctx, func(ctx context.Context) error {
		cm, err := g.getK8sConfigMap(ctx, vutils.K8sNS, installationConfigMapName)
		if k8serr.IsNotFound(err) {
			installation := cc.GetStatus().GetInstallation()
			if installation == nil {
				installation = &corev1.ClusterConfig_Status_Installation{}
			}
			data, err := pbutils.MarshalJSON(installation, true)
			if err != nil {
				return err
			}
			_, err = g.k8sC.CoreV1().ConfigMaps(vutils.K8sNS).Create(ctx, &corev1k8s.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: installationConfigMapName, Namespace: vutils.K8sNS, Annotations: expected},
				Data:       map[string]string{installationConfigMapKey: string(data)},
			}, metav1.CreateOptions{})
			if k8serr.IsAlreadyExists(err) {
				return k8serr.NewConflict(corev1k8s.Resource("configmaps"), installationConfigMapName, err)
			}
			return err
		}
		if err != nil {
			return err
		}
		if err := checkTargetAnnotations(cm.Annotations, expected); err != nil {
			return err
		}
		complete := true
		for key, value := range expected {
			complete = complete && cm.Annotations[key] == value
		}
		if complete {
			return nil
		}
		cm = cm.DeepCopy()
		if cm.Annotations == nil {
			cm.Annotations = make(map[string]string)
		}
		for key, value := range expected {
			cm.Annotations[key] = value
		}
		_, err = g.k8sC.CoreV1().ConfigMaps(vutils.K8sNS).Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}
