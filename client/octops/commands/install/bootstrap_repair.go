package install

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/client/octops/internal/k8sretry"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const initializationInputHashKey = "octelium.com/genesis-init-input-hash"
const initializationInputKey = "genesis-input-key"

func getBootstrapInput(ctx context.Context, c kubernetes.Interface, data map[string][]byte) (*k8scorev1.Secret, error) {
	source, err := getK8sSecret(ctx, c, genesisNS, "octelium-init")
	if k8serr.IsNotFound(err) {
		source, err = getK8sSecret(ctx, c, octeliumNS, "octelium-init")
	}
	if !k8serr.IsNotFound(err) {
		if err != nil || source.Namespace != genesisNS || len(source.Data[initializationInputKey]) != 0 || (source.Immutable != nil && *source.Immutable) || source.UID == "" || source.ResourceVersion == "" {
			return source, err
		}
		if err := checkBootstrapRepairState(ctx, c); err != nil {
			return source, nil
		}
		original := source
		key, err := utilrand.GetRandomBytes(32)
		if err != nil {
			return nil, err
		}
		err = k8sretry.Do(ctx, func(ctx context.Context) error {
			current, err := c.CoreV1().Secrets(genesisNS).Get(ctx, original.Name, k8smetav1.GetOptions{})
			if err != nil {
				return err
			}
			if current.UID != original.UID || current.DeletionTimestamp != nil {
				return errors.New("The bootstrap Secret changed before initialization")
			}
			if len(current.Data[initializationInputKey]) != 0 {
				source = current
				return nil
			}
			if err := checkBootstrapRepairState(ctx, c); err != nil {
				return err
			}
			current = current.DeepCopy()
			if current.Data == nil {
				current.Data = make(map[string][]byte)
			}
			current.Data[initializationInputKey] = key
			source, err = c.CoreV1().Secrets(genesisNS).Update(ctx, current, k8smetav1.UpdateOptions{})
			return err
		})
		if k8serr.IsForbidden(err) || k8serr.IsInvalid(err) {
			return original, nil
		}
		return source, err
	}
	key, err := utilrand.GetRandomBytes(32)
	if err != nil {
		return nil, err
	}
	desired := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: genesisNS}, Data: make(map[string][]byte)}
	for name, value := range data {
		desired.Data[name] = value
	}
	desired.Data[initializationInputKey] = key
	create := func() (*k8scorev1.Secret, error) {
		return k8sretry.Create(ctx, desired,
			func(ctx context.Context) (*k8scorev1.Secret, error) {
				return c.CoreV1().Secrets(genesisNS).Create(ctx, desired, k8smetav1.CreateOptions{})
			},
			func(ctx context.Context) (*k8scorev1.Secret, error) {
				return c.CoreV1().Secrets(genesisNS).Get(ctx, desired.Name, k8smetav1.GetOptions{})
			})
	}
	source, err = create()
	if k8serr.IsForbidden(err) || k8serr.IsInvalid(err) {
		delete(desired.Data, initializationInputKey)
		return create()
	}
	return source, err
}

func initializationInputBinding(hash string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hash))
	return hex.EncodeToString(mac.Sum(nil))
}

func bindInitializationInput(ctx context.Context, c kubernetes.Interface, desired *batchv1.Job, hash string, key []byte) (*batchv1.Job, error) {
	existing, err := getK8sJob(ctx, c, desired.Namespace, desired.Name)
	if err != nil && !k8serr.IsNotFound(err) {
		return nil, err
	}
	if err == nil && !genesisJobFinished(existing) && existing.Spec.Template.Annotations[initializationInputHashKey] == "" {
		data, err := json.Marshal(desired.Spec)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if existing.Annotations[genesisRequestHash] == hex.EncodeToString(sum[:]) {
			source, err := getK8sSecret(ctx, c, genesisNS, "octelium-init")
			if k8serr.IsNotFound(err) {
				source, err = getK8sSecret(ctx, c, octeliumNS, "octelium-init")
			}
			if err == nil {
				currentHash, err := initializationInputHash(source.Data)
				if err != nil {
					return nil, err
				}
				if currentHash == hash {
					return desired, nil
				}
			} else if k8serr.IsNotFound(err) {
				if existing.Spec.Suspend != nil && *existing.Spec.Suspend {
					return desired, nil
				}
			} else {
				return nil, err
			}
		}
	}
	if len(key) != 0 {
		desired.Spec.Template.Annotations = map[string]string{initializationInputHashKey: initializationInputBinding(hash, key)}
	}
	return desired, nil
}

func initializationInputHash(data map[string][]byte) (string, error) {
	bootstrap := &cbootstrapv1.Config{}
	if err := pbutils.Unmarshal(data["bootstrap"], bootstrap); err != nil {
		return "", err
	}
	var region *corev1.Region
	if data["region"] != nil {
		region = &corev1.Region{}
		if err := pbutils.Unmarshal(data["region"], region); err != nil {
			return "", err
		}
	}
	bootstrapBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(bootstrap)
	if err != nil {
		return "", err
	}
	regionBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(region)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(map[string][]byte{"bootstrap": bootstrapBytes, "region": regionBytes, "domain": []byte(string(data["domain"]))})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func repairBootstrap(ctx context.Context, c kubernetes.Interface, original *k8scorev1.Secret, desired map[string][]byte) error {
	differs := errors.New("The existing bootstrap differs. Refusing to replace input after initialization has started")
	if original.Namespace != genesisNS || original.UID == "" || original.ResourceVersion == "" || len(original.Data[initializationInputKey]) == 0 {
		return differs
	}
	oldHash, err := initializationInputHash(original.Data)
	if err != nil {
		return err
	}
	desiredHash, err := initializationInputHash(desired)
	if err != nil {
		return err
	}
	desiredBinding := initializationInputBinding(desiredHash, original.Data[initializationInputKey])
	job, err := getK8sJob(ctx, c, genesisNS, genesisJobName)
	if k8serr.IsNotFound(err) {
		return differs
	}
	if err != nil {
		return err
	}
	return k8sretry.Do(ctx, func(ctx context.Context) error {
		current, err := c.CoreV1().Secrets(genesisNS).Get(ctx, original.Name, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}
		if current.UID != original.UID || current.DeletionTimestamp != nil {
			return differs
		}
		currentHash, err := initializationInputHash(current.Data)
		if err != nil {
			return err
		}
		if currentHash == desiredHash {
			return nil
		}
		if currentHash != oldHash {
			return differs
		}
		reservation, err := getK8sJob(ctx, c, genesisNS, genesisJobName)
		if err != nil {
			return err
		}
		if reservation.UID != job.UID || reservation.UID == "" || reservation.DeletionTimestamp != nil ||
			reservation.Spec.Suspend == nil || !*reservation.Spec.Suspend || genesisJobFinished(reservation) ||
			reservation.Status.Active != 0 || reservation.Spec.Template.Annotations[initializationInputHashKey] != desiredBinding {
			return differs
		}
		if err := checkGenesisJobs(ctx, c, reservation); err != nil {
			return err
		}
		pods, err := c.CoreV1().Pods(genesisNS).List(ctx, k8smetav1.ListOptions{})
		if err != nil {
			return err
		}
		for _, pod := range pods.Items {
			owner := k8smetav1.GetControllerOf(&pod)
			if owner != nil && owner.Kind == "Job" && owner.UID == reservation.UID && pod.Status.Phase != k8scorev1.PodSucceeded && pod.Status.Phase != k8scorev1.PodFailed {
				return differs
			}
		}
		if err := checkBootstrapRepairState(ctx, c); err != nil {
			return err
		}
		latest, err := c.BatchV1().Jobs(genesisNS).Get(ctx, reservation.Name, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}
		if latest.UID != reservation.UID || latest.DeletionTimestamp != nil || latest.Spec.Suspend == nil || !*latest.Spec.Suspend {
			return differs
		}
		current = current.DeepCopy()
		for _, key := range []string{"bootstrap", "region", "domain"} {
			current.Data[key] = desired[key]
		}
		_, err = c.CoreV1().Secrets(genesisNS).Update(ctx, current, k8smetav1.UpdateOptions{})
		return err
	})
}

func checkBootstrapRepairState(ctx context.Context, c kubernetes.Interface) error {
	differs := errors.New("The existing bootstrap differs. Refusing to replace input after initialization has started")
	for _, name := range []string{"octelium-init", "init-token", "octelium-postgres", "octelium-redis"} {
		if _, err := getK8sSecret(ctx, c, octeliumNS, name); err == nil {
			return differs
		} else if !k8serr.IsNotFound(err) {
			return err
		}
	}
	if _, err := getK8sConfigMap(ctx, c, octeliumNS, installationConfigMapName); err == nil {
		return differs
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if checkpoint, err := getK8sSecret(ctx, c, octeliumNS, "octelium-genesis-init"); err == nil {
		if checkpoint.DeletionTimestamp != nil || checkpoint.Annotations["octelium.com/genesis-init-complete"] == "true" ||
			string(checkpoint.Data["version"]) != "1" || string(checkpoint.Data["id"]) == "" ||
			len(checkpoint.Data["input-hash"]) != sha256.Size*2 {
			return differs
		}
		if _, err := hex.DecodeString(string(checkpoint.Data["input-hash"])); err != nil {
			return differs
		}
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	return nil
}
