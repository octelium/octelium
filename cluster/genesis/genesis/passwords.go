package genesis

import (
	"context"
	"strings"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/pkg/errors"
	k8scorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type storagePasswords struct {
	postgres string
	redis    string
}

func validatePasswordSecretReference(name, namespace, key string) error {
	if name == "" {
		return errors.New("name of passwordFromSecret is empty")
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return errors.Errorf("Invalid passwordFromSecret name %q: %s", name, strings.Join(errs, ", "))
	}
	if namespace != "" {
		if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
			return errors.Errorf("Invalid passwordFromSecret namespace %q: %s", namespace, strings.Join(errs, ", "))
		}
	}
	if key != "" {
		if errs := validation.IsConfigMapKey(key); len(errs) > 0 {
			return errors.Errorf("Invalid passwordFromSecret key %q: %s", key, strings.Join(errs, ", "))
		}
	}
	return nil
}

func (g *Genesis) resolveStoragePasswords(ctx context.Context, bs *cbootstrapv1.Config) (*storagePasswords, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if bs.GetSpec() == nil {
		return nil, errors.New("Nil Bootstrap")
	}
	pg := bs.Spec.GetPrimaryStorage().GetPostgresql()
	if pg == nil {
		return nil, errors.New("No Postgres info")
	}
	redis := bs.Spec.GetSecondaryStorage().GetRedis()
	if redis == nil {
		return nil, errors.New("No Redis info")
	}

	secrets := make(map[string]*k8scorev1.Secret)
	getPassword := func(name, namespace, key string) (string, error) {
		if err := validatePasswordSecretReference(name, namespace, key); err != nil {
			return "", err
		}
		if namespace == "" {
			namespace = "default"
		}
		identity := namespace + "/" + name
		secret := secrets[identity]
		if secret == nil {
			var err error
			secret, err = g.getK8sSecret(ctx, namespace, name)
			if err != nil {
				return "", err
			}
			secrets[identity] = secret
		}
		if key != "" {
			if len(secret.Data[key]) == 0 {
				return "", errors.Errorf("The passwordFromSecret %s key %q is missing or empty", identity, key)
			}
			return string(secret.Data[key]), nil
		}
		for _, key := range []string{"password", "data"} {
			if len(secret.Data[key]) > 0 {
				return string(secret.Data[key]), nil
			}
		}
		return "", errors.Errorf("The passwordFromSecret %s has no non-empty password or data key", identity)
	}

	ret := &storagePasswords{}
	var err error
	switch value := pg.PasswordType.(type) {
	case *cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password:
		if value != nil {
			ret.postgres = value.Password
		}
	case *cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_:
		if value == nil {
			return nil, errors.New("name of passwordFromSecret is empty")
		}
		ref := value.PasswordFromSecret
		ret.postgres, err = getPassword(ref.GetName(), ref.GetNamespace(), ref.GetKey())
		if err != nil {
			return nil, errors.Wrap(err, "Could not resolve the Postgres password")
		}
	}
	switch value := redis.PasswordType.(type) {
	case *cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password:
		if value != nil {
			ret.redis = value.Password
		}
	case *cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_:
		if value == nil {
			return nil, errors.New("name of passwordFromSecret is empty")
		}
		ref := value.PasswordFromSecret
		ret.redis, err = getPassword(ref.GetName(), ref.GetNamespace(), ref.GetKey())
		if err != nil {
			return nil, errors.Wrap(err, "Could not resolve the Redis password")
		}
	}
	return ret, nil
}
