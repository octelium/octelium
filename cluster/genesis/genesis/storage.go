package genesis

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

func setStorageEnvironment(bootstrap *cbootstrapv1.Config, passwords *storagePasswords) {
	pg := bootstrap.Spec.PrimaryStorage.GetPostgresql()
	if ldflags.IsTest() {
		os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
		os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
		os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
		os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")
	} else {
		for key, value := range map[string]string{
			"OCTELIUM_POSTGRES_DATABASE": pg.Database,
			"OCTELIUM_POSTGRES_USERNAME": pg.Username,
			"OCTELIUM_POSTGRES_PASSWORD": passwords.postgres,
			"OCTELIUM_POSTGRES_HOST":     pg.Host,
		} {
			if value != "" {
				os.Setenv(key, value)
			}
		}
		if !pg.IsTLS {
			os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
		}
		if pg.Port != 0 {
			os.Setenv("OCTELIUM_POSTGRES_PORT", fmt.Sprintf("%d", pg.Port))
		}
	}
	redis := bootstrap.Spec.SecondaryStorage.GetRedis()
	for key, value := range map[string]string{
		"OCTELIUM_REDIS_USERNAME": redis.Username,
		"OCTELIUM_REDIS_PASSWORD": passwords.redis,
		"OCTELIUM_REDIS_HOST":     redis.Host,
	} {
		if value != "" {
			os.Setenv(key, value)
		}
	}
	if redis.Database != 0 {
		os.Setenv("OCTELIUM_REDIS_DATABASE", fmt.Sprintf("%d", redis.Database))
	}
	if redis.Port != 0 {
		os.Setenv("OCTELIUM_REDIS_PORT", fmt.Sprintf("%d", redis.Port))
	}
	if redis.IsTLS {
		os.Setenv("OCTELIUM_REDIS_USE_TLS", "true")
	}
}

type initializationDialer struct {
	ctx       context.Context
	tlsConfig *tls.Config
}

type initializationConn struct {
	net.Conn
	stop func() bool
}

func (c *initializationConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func (d *initializationDialer) dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if d.tlsConfig == nil {
		conn, err = dialer.DialContext(ctx, network, address)
	} else {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: d.tlsConfig}).DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	return &initializationConn{Conn: conn, stop: context.AfterFunc(d.ctx, func() { conn.Close() })}, nil
}

func (d *initializationDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(d.ctx, network, address, 0)
}

func (d *initializationDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return d.dial(d.ctx, network, address, timeout)
}

func (d *initializationDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address, 0)
}

func preflightInitializationStorage(ctx context.Context, bootstrap *cbootstrapv1.Config, passwords *storagePasswords) error {
	setStorageEnvironment(bootstrap, passwords)
	return k8sretry.Do(ctx, func(ctx context.Context) error {
		db, err := postgresutils.NewDBWithDialer(&initializationDialer{ctx: ctx})
		if err != nil {
			return errors.Wrap(err, "Could not configure PostgreSQL")
		}
		defer db.Close()
		if err := db.PingContext(ctx); err != nil {
			return errors.Wrap(err, "Could not connect to PostgreSQL before initialization")
		}
		opts := redisutils.NewOptions()
		opts.ContextTimeoutEnabled = true
		opts.Dialer = (&initializationDialer{ctx: ctx, tlsConfig: opts.TLSConfig}).DialContext
		redisC := redis.NewClient(opts)
		defer redisC.Close()
		stop := context.AfterFunc(ctx, func() { redisC.Close() })
		defer stop()
		if err := redisC.Ping(ctx).Err(); err != nil {
			return errors.Wrap(err, "Could not connect to Redis before initialization")
		}
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&exists); err != nil {
			return err
		}
		if exists {
			var empty bool
			if err := db.QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM octelium_resources)`).Scan(&empty); err != nil {
				return err
			}
			if !empty {
				return errors.New("The primary storage contains existing resources. Use octops upgrade instead of init")
			}
		}
		for _, pattern := range []string{"octelium:*", "rsc:*"} {
			var cursor uint64
			for {
				keys, next, err := redisC.Scan(ctx, cursor, pattern, 100).Result()
				if err != nil {
					return err
				}
				if len(keys) > 0 {
					return errors.New("The Redis database contains existing Octelium state. Refusing to reset it")
				}
				cursor = next
				if cursor == 0 {
					break
				}
			}
		}
		return nil
	})
}
