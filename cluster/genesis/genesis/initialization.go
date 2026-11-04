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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const initializationSecretName = "octelium-genesis-init"
const initializationIDKey = "octelium.com/genesis-init-id"
const initializationCompleteKey = "octelium.com/genesis-init-complete"
const initializationRedisKey = "octelium:genesis:init"
const initializationInputHashKey = "octelium.com/genesis-init-input-hash"
const initializationInputKey = "genesis-input-key"

func initializationInputBinding(hash string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hash))
	return hex.EncodeToString(mac.Sum(nil))
}

type initialization struct {
	id            string
	inputHash     string
	aesKeyName    string
	complete      bool
	clusterConfig *corev1.ClusterConfig
	region        *corev1.Region
	passwords     *storagePasswords
}

func initializationInputHash(cr *LoadedClusterResource) (string, error) {
	bootstrap, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cr.Bootstrap)
	if err != nil {
		return "", err
	}
	region, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cr.Region)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(map[string][]byte{
		"bootstrap": bootstrap,
		"region":    region,
		"domain":    []byte(cr.Domain),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (g *Genesis) loadInitializationInput(ctx context.Context) (*LoadedClusterResource, error) {
	cr, err := g.loadClusterInitResources(ctx, "default")
	if k8serr.IsNotFound(err) {
		return g.loadClusterInitResources(ctx, vutils.K8sNS)
	}
	return cr, err
}

func (g *Genesis) prepareInitialization(ctx context.Context, cr *LoadedClusterResource) (*initialization, error) {
	return g.prepareInitializationWithPreflight(ctx, cr, nil)
}

func (g *Genesis) prepareInitializationWithPreflight(ctx context.Context, cr *LoadedClusterResource, preflight func(context.Context, *storagePasswords) error) (*initialization, error) {
	if cr == nil || cr.Bootstrap.GetSpec().GetPrimaryStorage().GetPostgresql() == nil ||
		cr.Bootstrap.GetSpec().GetSecondaryStorage().GetRedis() == nil {
		return nil, errors.Errorf("The bootstrap must contain PostgreSQL and Redis storage configuration")
	}
	if err := checkTargetDomain(os.Getenv("OCTELIUM_DOMAIN"), cr.Domain); err != nil {
		return nil, err
	}

	inputHash, err := initializationInputHash(cr)
	if err != nil {
		return nil, err
	}

	var replacement *k8scorev1.Secret
	secret, err := g.getK8sSecret(ctx, vutils.K8sNS, initializationSecretName)
	if err == nil {
		init, err := decodeInitialization(secret, inputHash)
		if err != nil {
			savedHash := string(secret.Data["input-hash"])
			if savedHash == inputHash || secret.Annotations[initializationCompleteKey] == "true" ||
				secret.UID == "" || secret.ResourceVersion == "" || len(savedHash) != sha256.Size*2 {
				return nil, err
			}
			if _, decodeErr := hex.DecodeString(savedHash); decodeErr != nil {
				return nil, err
			}
			if _, decodeErr := decodeInitialization(secret, savedHash); decodeErr != nil {
				return nil, decodeErr
			}
			replacement = secret
		}
		if err := g.validateInitializationNamespace(ctx, secret); err != nil {
			return nil, err
		}
		if replacement == nil {
			if !init.complete {
				init.passwords, err = g.resolveStoragePasswords(ctx, cr.Bootstrap)
				if err != nil {
					return nil, err
				}
			}
			if err := g.setNamespace(ctx); err != nil {
				return nil, err
			}
			return init, nil
		}
	} else if !k8serr.IsNotFound(err) {
		return nil, err
	}

	if err := g.checkInitializationNotStarted(ctx); err != nil {
		return nil, err
	}

	input := *cr
	if cr.Region != nil {
		input.Region = proto.Clone(cr.Region).(*corev1.Region)
	}
	region, err := g.initRegion(&input)
	if err != nil {
		return nil, err
	}
	clusterCfg, err := g.initClusterConfig(ctx, cr.Bootstrap, cr.Domain)
	if err != nil {
		return nil, err
	}
	if err := g.validateClusterNetwork(ctx, clusterCfg, cr.Bootstrap); err != nil {
		return nil, err
	}
	passwords, err := g.resolveStoragePasswords(ctx, cr.Bootstrap)
	if err != nil {
		return nil, err
	}
	if preflight != nil {
		if err := preflight(ctx, passwords); err != nil {
			return nil, err
		}
	}
	if err := g.setNamespace(ctx); err != nil {
		return nil, err
	}
	namespace, err := k8sretry.Read(ctx, func(ctx context.Context) (*k8scorev1.Namespace, error) {
		return g.k8sC.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
	})
	if err != nil {
		return nil, err
	}
	id := vutils.UUIDv4()
	clusterCfg.Metadata.Annotations = map[string]string{initializationIDKey: id}
	if region.Metadata.Annotations == nil {
		region.Metadata.Annotations = make(map[string]string)
	}
	region.Metadata.Annotations[initializationIDKey] = id

	secret = &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      initializationSecretName,
			Namespace: vutils.K8sNS,
		},
		Immutable: new(true),
		Data: map[string][]byte{
			"version":       []byte("1"),
			"id":            []byte(id),
			"input-hash":    []byte(inputHash),
			"aes-key-name":  []byte("sys:aes256-key-" + utilrand.GetRandomStringLowercase(8)),
			"clusterConfig": pbutils.MarshalMust(clusterCfg),
			"region":        pbutils.MarshalMust(region),
		},
	}
	if namespace.UID != "" {
		secret.Data["namespace-uid"] = []byte(namespace.UID)
	}
	if replacement != nil {
		if err := g.checkInitializationNotStarted(ctx); err != nil {
			return nil, err
		}
		if err := k8sretry.Delete(ctx, replacement,
			func(ctx context.Context) (*k8scorev1.Secret, error) {
				return g.k8sC.CoreV1().Secrets(vutils.K8sNS).Get(ctx, initializationSecretName, k8smetav1.GetOptions{})
			},
			func(ctx context.Context, options k8smetav1.DeleteOptions) error {
				return g.k8sC.CoreV1().Secrets(vutils.K8sNS).Delete(ctx, initializationSecretName, options)
			}); err != nil {
			return nil, err
		}
	}
	desired := secret
	secret, err = k8sretry.Create(ctx, desired,
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, desired, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return g.k8sC.CoreV1().Secrets(vutils.K8sNS).Get(ctx, initializationSecretName, k8smetav1.GetOptions{})
		})
	if err != nil {
		return nil, err
	}
	init, err := decodeInitialization(secret, inputHash)
	if err != nil {
		return nil, err
	}
	init.passwords = passwords
	return init, nil
}

func (g *Genesis) checkInitializationNotStarted(ctx context.Context) error {
	for _, name := range []string{"octelium-init", "init-token", "octelium-postgres", "octelium-redis"} {
		if _, err := g.getK8sSecret(ctx, vutils.K8sNS, name); err == nil {
			return errors.Errorf("An existing Cluster installation was found. Use octops upgrade instead of init")
		} else if !k8serr.IsNotFound(err) {
			return err
		}
	}
	if _, err := g.getK8sConfigMap(ctx, vutils.K8sNS, installationConfigMapName); err == nil {
		return errors.Errorf("An existing Cluster installation was found. Use octops upgrade instead of init")
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	return nil
}

func decodeInitialization(secret *k8scorev1.Secret, inputHash string) (*initialization, error) {
	ret := &initialization{
		id:            string(secret.Data["id"]),
		inputHash:     string(secret.Data["input-hash"]),
		aesKeyName:    string(secret.Data["aes-key-name"]),
		complete:      secret.Annotations[initializationCompleteKey] == "true",
		clusterConfig: &corev1.ClusterConfig{},
		region:        &corev1.Region{},
	}
	if ret.aesKeyName == "" {
		ret.aesKeyName = "sys:aes256-key-genesis"
	}
	if string(secret.Data["version"]) != "1" || ret.id == "" || ret.inputHash == "" {
		return nil, errors.Errorf("Invalid genesis initialization state")
	}
	if ret.inputHash != inputHash {
		return nil, errors.Errorf("The bootstrap differs from the existing initialization. Refusing to replace Cluster state")
	}
	if err := pbutils.Unmarshal(secret.Data["clusterConfig"], ret.clusterConfig); err != nil {
		return nil, err
	}
	if err := pbutils.Unmarshal(secret.Data["region"], ret.region); err != nil {
		return nil, err
	}
	if ret.clusterConfig.GetMetadata().GetName() != "default" || ret.clusterConfig.GetStatus() == nil ||
		ret.clusterConfig.GetMetadata().GetAnnotations()[initializationIDKey] != ret.id ||
		ret.region.GetMetadata().GetName() == "" || ret.region.GetStatus() == nil ||
		ret.region.GetMetadata().GetAnnotations()[initializationIDKey] != ret.id {
		return nil, errors.Errorf("Invalid genesis initialization resources")
	}
	if !ret.complete && ret.region.Status.Version != ldflags.GetVersion() {
		return nil, errors.Errorf("Resume initialization with version %s before upgrading the Cluster", ret.region.Status.Version)
	}
	return ret, nil
}

func (g *Genesis) completeInitialization(ctx context.Context, init *initialization) error {
	return k8sretry.Do(ctx, func(ctx context.Context) error {
		secret, err := g.getK8sSecret(ctx, vutils.K8sNS, initializationSecretName)
		if err != nil {
			return err
		}
		if _, err := decodeInitialization(secret, init.inputHash); err != nil {
			return err
		}
		if string(secret.Data["id"]) != init.id {
			return errors.Errorf("The genesis initialization identity changed")
		}
		if secret.Annotations[initializationCompleteKey] == "true" {
			return nil
		}
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations[initializationCompleteKey] = "true"
		_, err = g.k8sC.CoreV1().Secrets(vutils.K8sNS).Update(ctx, secret, k8smetav1.UpdateOptions{})
		return err
	})
}

func lockInitialization(ctx context.Context, db *sql.DB) (func(), error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtext('octelium'), hashtext('genesis-init'))`).Scan(&locked); err != nil {
		conn.Close()
		return nil, err
	}
	if !locked {
		conn.Close()
		return nil, errors.Errorf("Another genesis initialization is using the primary storage")
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtext('octelium'), hashtext('genesis-init'))`)
		conn.Close()
	}, nil
}

func getInitializationResource(ctx context.Context, db *sql.DB, kind, name string, out proto.Message) error {
	var data []byte
	err := db.QueryRowContext(ctx,
		`SELECT resource FROM octelium_resources WHERE api = $1 AND version = $2 AND kind = $3 AND resource->'metadata'->>'name' = $4`,
		ucorev1.API, ucorev1.Version, kind, name).Scan(&data)
	if err != nil {
		return err
	}
	return pbutils.UnmarshalJSON(data, out)
}

func claimInitializationRedis(ctx context.Context, c *redis.Client, id string) error {
	owner, err := c.Get(ctx, initializationRedisKey).Result()
	if err == nil {
		if owner != id {
			return errors.Errorf("The Redis database belongs to another Cluster initialization")
		}
		return nil
	} else if !errors.Is(err, redis.Nil) {
		return err
	}

	for _, pattern := range []string{"octelium:*", "rsc:*"} {
		var cursor uint64
		for {
			keys, next, err := c.Scan(ctx, cursor, pattern, 100).Result()
			if err != nil {
				return err
			}
			if len(keys) > 0 {
				return errors.Errorf("The Redis database contains existing Octelium state. Refusing to reset it")
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}
	claimed, err := c.SetNX(ctx, initializationRedisKey, id, 0).Result()
	if err != nil {
		return err
	}
	if !claimed {
		owner, err := c.Get(ctx, initializationRedisKey).Result()
		if err != nil {
			return err
		}
		if owner != id {
			return errors.Errorf("Another Cluster initialization claimed the Redis database")
		}
	}
	return nil
}

func initializeClusterResources(ctx context.Context, srv *rscserver.Server, init *initialization) (*genesisutils.InstallCtx, error) {
	cc := &corev1.ClusterConfig{}
	err := getInitializationResource(ctx, srv.GetDB(), ucorev1.KindClusterConfig, "default", cc)
	if errors.Is(err, sql.ErrNoRows) {
		var empty bool
		if err := srv.GetDB().QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM octelium_resources)`).Scan(&empty); err != nil {
			return nil, err
		}
		if !empty {
			return nil, errors.Errorf("The primary storage contains existing resources. Refusing to reset it")
		}
	} else if err != nil {
		return nil, err
	} else if cc.GetMetadata().GetAnnotations()[initializationIDKey] != init.id ||
		cc.GetStatus().GetDomain() != init.clusterConfig.Status.Domain {
		return nil, errors.Errorf("The primary storage belongs to an existing Cluster. Use octops upgrade instead of init")
	}

	if err := claimInitializationRedis(ctx, srv.GetRedisC(), init.id); err != nil {
		return nil, err
	}
	if cc.GetMetadata() == nil {
		created, err := srv.CreateResource(ctx, init.clusterConfig, ucorev1.API, ucorev1.Version, ucorev1.KindClusterConfig)
		if err != nil {
			return nil, err
		}
		cc = created.(*corev1.ClusterConfig)
	}

	region := &corev1.Region{}
	err = getInitializationResource(ctx, srv.GetDB(), ucorev1.KindRegion, init.region.Metadata.Name, region)
	if errors.Is(err, sql.ErrNoRows) {
		created, err := srv.CreateResource(ctx, init.region, ucorev1.API, ucorev1.Version, ucorev1.KindRegion)
		if err != nil {
			return nil, err
		}
		region = created.(*corev1.Region)
	} else if err != nil {
		return nil, err
	} else if region.GetMetadata().GetAnnotations()[initializationIDKey] != init.id {
		return nil, errors.Errorf("The Region belongs to another initialization")
	}

	return &genesisutils.InstallCtx{ClusterConfig: cc, Region: region}, nil
}

func createInitResource[T umetav1.ResourceObjectI](ctx context.Context, resource T,
	get func(context.Context, *rmetav1.GetOptions, ...grpc.CallOption) (T, error),
	create func(context.Context, T, ...grpc.CallOption) (T, error),
) (T, error) {
	existing, err := get(ctx, &rmetav1.GetOptions{Name: resource.GetMetadata().Name})
	if err == nil || !grpcerr.IsNotFound(err) {
		return existing, err
	}
	created, err := create(ctx, resource)
	if grpcerr.AlreadyExists(err) {
		return get(ctx, &rmetav1.GetOptions{Name: resource.GetMetadata().Name})
	}
	return created, err
}

func (g *Genesis) createStorageSecret(ctx context.Context, secret *k8scorev1.Secret) error {
	existing, err := k8sretry.Create(ctx, secret,
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, secret, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return g.k8sC.CoreV1().Secrets(vutils.K8sNS).Get(ctx, secret.Name, k8smetav1.GetOptions{})
		})
	if err != nil {
		return err
	}
	for key, value := range secret.Data {
		if got, ok := existing.Data[key]; !ok || !bytes.Equal(got, value) {
			return errors.Errorf("The existing storage Secret %s differs from the bootstrap. Refusing to replace it", secret.Name)
		}
	}
	return nil
}

func (g *Genesis) getInitAuthenticationToken(ctx context.Context) (*k8scorev1.Secret, error) {
	secret, err := g.getK8sSecret(ctx, vutils.K8sNS, "init-token")
	if err != nil {
		return nil, err
	}
	if secret.Annotations[initializationIDKey] != g.initializationID || len(secret.Data["data"]) == 0 {
		return nil, errors.Errorf("The initial authentication token does not belong to this initialization or is empty")
	}
	return secret, nil
}

func equalInitializationSecrets(a, b *k8scorev1.Secret) bool {
	if a.Type != b.Type || !bytes.Equal(a.Data["domain"], b.Data["domain"]) {
		return false
	}
	for _, field := range []string{"bootstrap", "region"} {
		var left, right proto.Message
		if field == "bootstrap" {
			left, right = &cbootstrapv1.Config{}, &cbootstrapv1.Config{}
		} else {
			left, right = &corev1.Region{}, &corev1.Region{}
		}
		if pbutils.Unmarshal(a.Data[field], left) != nil || pbutils.Unmarshal(b.Data[field], right) != nil || !proto.Equal(left, right) {
			return false
		}
	}
	return true
}
