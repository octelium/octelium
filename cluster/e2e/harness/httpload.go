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

package harness

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const RequestIDHeader = "X-E2e-Request-Id"

type CountingUpstream struct {
	Addr     string
	BodySize int

	srv *http.Server
	lis net.Listener

	total    atomic.Int64
	inFlight atomic.Int64
	peak     atomic.Int64

	mu   sync.Mutex
	seen map[string]int
}

func NewCountingUpstream(listenAddr string, bodySize int) (*CountingUpstream, error) {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	ret := &CountingUpstream{
		Addr:     lis.Addr().String(),
		BodySize: bodySize,
		lis:      lis,
		seen:     map[string]int{},
	}

	body := []byte(strings.Repeat("o", max(bodySize, 2)))

	ret.srv = &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ret.total.Add(1)
			cur := ret.inFlight.Add(1)
			defer ret.inFlight.Add(-1)
			for {
				old := ret.peak.Load()
				if cur <= old || ret.peak.CompareAndSwap(old, cur) {
					break
				}
			}

			if id := r.Header.Get(RequestIDHeader); id != "" {
				ret.mu.Lock()
				ret.seen[id]++
				ret.mu.Unlock()
			}

			if r.Body != nil {
				io.Copy(io.Discard, r.Body)
			}

			if ms, err := strconv.Atoi(r.URL.Query().Get("holdMs")); err == nil && ms > 0 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(time.Duration(ms) * time.Millisecond):
				}
			}

			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write(body)
		}),
	}

	go ret.srv.Serve(lis)

	return ret, nil
}

func (h *H) StartCountingUpstream(t *testing.T, bodySize int) *CountingUpstream {
	t.Helper()

	host := h.ExternalIP
	if host == "" {
		host = "127.0.0.1"
	}

	ret, err := NewCountingUpstream(net.JoinHostPort(host, "0"), bodySize)
	if err != nil {
		t.Fatalf("Could not start the counting upstream: %+v", err)
	}

	t.Cleanup(ret.Close)
	return ret
}

func (u *CountingUpstream) URL() string { return "http://" + u.Addr }

func (u *CountingUpstream) Total() int64 { return u.total.Load() }

func (u *CountingUpstream) PeakInFlight() int64 { return u.peak.Load() }

func (u *CountingUpstream) Seen(id string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.seen[id]
}

func (u *CountingUpstream) SeenWithPrefix(prefix string) int {
	u.mu.Lock()
	defer u.mu.Unlock()

	var ret int
	for id, n := range u.seen {
		if strings.HasPrefix(id, prefix) {
			ret += n
		}
	}
	return ret
}

func (u *CountingUpstream) Duplicates() []string {
	u.mu.Lock()
	defer u.mu.Unlock()

	var ret []string
	for id, n := range u.seen {
		if n > 1 {
			ret = append(ret, id)
		}
	}
	sort.Strings(ret)
	return ret
}

func (u *CountingUpstream) Close() {
	u.srv.Close()
	u.lis.Close()
}

type HTTPRequestSpec struct {
	Token string
	Class string
	ID    string
	Path  string
}

type HTTPLoadOpts struct {
	URL      string
	Workers  int
	Duration time.Duration
	Requests int
	Timeout  time.Duration

	HTTP2             bool
	NewConnPerRequest bool

	Request func(worker, iteration int) HTTPRequestSpec
}

type HTTPLoadResult struct {
	*PoolResult

	mu       sync.Mutex
	byClass  map[string]map[int]int
	classLat map[string]*Latencies
}

func (r *HTTPLoadResult) record(class string, code int, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.byClass[class] == nil {
		r.byClass[class] = map[int]int{}
		r.classLat[class] = &Latencies{}
	}
	r.byClass[class][code]++
	r.classLat[class].Add(d)
}

func (r *HTTPLoadResult) Status(class string) map[int]int {
	r.mu.Lock()
	defer r.mu.Unlock()

	ret := map[int]int{}
	for k, v := range r.byClass[class] {
		ret[k] = v
	}
	return ret
}

func (r *HTTPLoadResult) Classes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	ret := make([]string, 0, len(r.byClass))
	for k := range r.byClass {
		ret = append(ret, k)
	}
	sort.Strings(ret)
	return ret
}

func (r *HTTPLoadResult) ClassLatency(class string) LatencySummary {
	r.mu.Lock()
	lat := r.classLat[class]
	r.mu.Unlock()

	if lat == nil {
		return LatencySummary{}
	}
	return lat.Summary()
}

func (r *HTTPLoadResult) Count(class string, codes ...int) int {
	status := r.Status(class)

	var ret int
	for _, code := range codes {
		ret += status[code]
	}
	return ret
}

func (r *HTTPLoadResult) CountOther(class string, codes ...int) int {
	var ret int
	for code, n := range r.Status(class) {
		isKnown := false
		for _, c := range codes {
			if c == code {
				isKnown = true
			}
		}
		if !isKnown {
			ret += n
		}
	}
	return ret
}

func (r *HTTPLoadResult) String() string {
	var b strings.Builder
	b.WriteString(r.PoolResult.String())
	for _, class := range r.Classes() {
		fmt.Fprintf(&b, "\n  %s: status=%v latency %s", class, r.Status(class), r.ClassLatency(class))
	}
	return b.String()
}

func (h *H) ingressTransport(timeout time.Duration, isHTTP2, disableKeepAlive bool,
	maxConns int) (http.RoundTripper, error) {
	roots, err := h.TLSRoots()
	if err != nil {
		return nil, err
	}

	addr := h.IngressAddr()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", addr)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}

	if isHTTP2 {
		return &http2.Transport{
			TLSClientConfig: tlsCfg,
			DialTLSContext: func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
				raw, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				conn := tls.Client(raw, cfg)
				if err := conn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return conn, nil
			},
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     10 * time.Second,
		}, nil
	}

	return &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   timeout,
		DisableKeepAlives:     disableKeepAlive,
		MaxIdleConns:          maxConns,
		MaxIdleConnsPerHost:   maxConns,
		MaxConnsPerHost:       maxConns,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}, nil
}

func (h *H) HTTPLoad(ctx context.Context, o HTTPLoadOpts) (*HTTPLoadResult, error) {
	if o.Workers <= 0 {
		o.Workers = 1
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.Request == nil {
		o.Request = func(worker, iteration int) HTTPRequestSpec { return HTTPRequestSpec{Class: "default"} }
	}

	base, err := url.Parse(o.URL)
	if err != nil {
		return nil, err
	}

	var shared http.RoundTripper
	if o.HTTP2 {
		shared, err = h.ingressTransport(o.Timeout, true, false, 0)
		if err != nil {
			return nil, err
		}
	}

	clients := make([]*http.Client, o.Workers)
	for i := range clients {
		rt := shared
		if rt == nil {
			rt, err = h.ingressTransport(o.Timeout, false, o.NewConnPerRequest, 1)
			if err != nil {
				return nil, err
			}
		}
		clients[i] = &http.Client{Transport: rt, Timeout: o.Timeout}
	}

	defer func() {
		for _, c := range clients {
			c.CloseIdleConnections()
		}
	}()

	ret := &HTTPLoadResult{
		byClass:  map[string]map[int]int{},
		classLat: map[string]*Latencies{},
	}

	do := func(ctx context.Context, worker, iteration int) error {
		spec := o.Request(worker, iteration)

		target := *base
		if spec.Path != "" {
			ref, err := url.Parse(spec.Path)
			if err != nil {
				return err
			}
			target = *base.ResolveReference(ref)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return err
		}
		if spec.Token != "" {
			req.Header.Set("Authorization", "Bearer "+spec.Token)
		}
		if spec.ID != "" {
			req.Header.Set(RequestIDHeader, spec.ID)
		}

		started := time.Now()
		res, err := clients[worker].Do(req)
		if err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}

		ret.record(spec.Class, res.StatusCode, time.Since(started))
		return nil
	}

	if o.Requests > 0 {
		ret.PoolResult = ForEach(ctx, o.Requests, o.Workers, func(ctx context.Context, i int) error {
			return do(ctx, i%o.Workers, i)
		})
		return ret, nil
	}

	ret.PoolResult = RunFor(ctx, o.Duration, o.Workers, do)
	return ret, nil
}

type SlowClientResult struct {
	Opened   int
	Closed   int
	Lifetime *Latencies
	Errors   *ErrorCounter
}

func (r *SlowClientResult) String() string {
	return fmt.Sprintf("%d opened, %d closed by the server, lifetime %s. %s",
		r.Opened, r.Closed, r.Lifetime.Summary(), r.Errors)
}

func (h *H) SlowClients(ctx context.Context, host string, conns int,
	observe time.Duration, slowBody bool) (*SlowClientResult, error) {
	roots, err := h.TLSRoots()
	if err != nil {
		return nil, err
	}

	ret := &SlowClientResult{
		Lifetime: &Latencies{},
		Errors:   NewErrorCounter(),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(ctx, observe)
	defer cancel()

	for range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()

			raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", h.IngressAddr())
			if err != nil {
				ret.Errors.Add(err)
				return
			}
			defer raw.Close()

			conn := tls.Client(raw, &tls.Config{
				ServerName: host,
				RootCAs:    roots,
				NextProtos: []string{"http/1.1"},
				MinVersion: tls.VersionTLS12,
			})
			if err := conn.HandshakeContext(ctx); err != nil {
				ret.Errors.Add(err)
				return
			}

			mu.Lock()
			ret.Opened++
			mu.Unlock()

			opened := time.Now()

			head := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: octelium-e2e-slowloris\r\n", host)
			if slowBody {
				head = fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\n"+
					"Content-Length: 1048576\r\n\r\n", host)
			}
			if _, err := conn.Write([]byte(head)); err != nil {
				ret.Errors.Add(err)
				return
			}

			closed := make(chan struct{})
			go func() {
				defer close(closed)
				br := bufio.NewReader(conn)
				for {
					if _, err := br.ReadByte(); err != nil {
						return
					}
				}
			}()

			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-closed:
					mu.Lock()
					ret.Closed++
					mu.Unlock()
					ret.Lifetime.Add(time.Since(opened))
					return
				case <-ticker.C:
					chunk := "X-E2e-Slow: 1\r\n"
					if slowBody {
						chunk = "x"
					}
					conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, err := conn.Write([]byte(chunk)); err != nil {
						<-closed
						mu.Lock()
						ret.Closed++
						mu.Unlock()
						ret.Lifetime.Add(time.Since(opened))
						return
					}
				}
			}
		}()
	}

	wg.Wait()

	return ret, nil
}
