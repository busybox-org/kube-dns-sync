package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/proxy"
	"k8s.io/klog/v2"
)

func init() {
	proxy.RegisterDialerType("http", httpDialType)
}

type httpDialer struct {
	addr    string
	header  http.Header
	forward proxy.Dialer
}

func httpDialType(u *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	var header http.Header
	if uu := u.User; uu != nil {
		passwd, _ := uu.Password()
		up := uu.Username() + ":" + passwd
		authz := "Basic " + base64.StdEncoding.EncodeToString([]byte(up))
		header = map[string][]string{
			"Proxy-Authorization": {authz},
		}
	}
	return &httpDialer{
		addr:    u.Host,
		header:  header,
		forward: forward,
	}, nil
}

func (d *httpDialer) Dial(network, addr string) (c net.Conn, err error) {
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: d.header,
	}
	c, err = d.forward.Dial(network, d.addr)
	if err != nil {
		return
	}
	_ = req.Write(c)

	// Read response until "\r\n\r\n".
	// bufio cannot be used as the connected server may not be
	// a HTTP(S) server.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 0, 4096)
	b := make([]byte, 1)
	state := 0
	for {
		_, e := c.Read(b)
		if e != nil {
			_ = c.Close()
			return nil, errors.New("reset proxy connection")
		}
		buf = append(buf, b[0])
		switch state {
		case 0:
			if b[0] == byte('\r') {
				state++
			}
			continue
		case 1:
			if b[0] == byte('\n') {
				state++
			} else {
				state = 0
			}
			continue
		case 2:
			if b[0] == byte('\r') {
				state++
			} else {
				state = 0
			}
			continue
		case 3:
			if b[0] == byte('\n') {
				goto PARSE
			} else {
				state = 0
			}
		}
	}

PARSE:
	var zero time.Time
	_ = c.SetReadDeadline(zero)
	resp, e := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(buf)), req)
	if e != nil {
		_ = c.Close()
		return nil, e
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		_ = c.Close()
		return nil, fmt.Errorf("proxy returns %s", resp.Status)
	}

	return c, nil
}

func CustomDNSResolver(dnsServer string) *net.Resolver {
	s := os.Getenv(dnsServer)
	if s != "" {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("udp", s)
			},
		}
	}

	return &net.Resolver{}
}

var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

var defaultTransport = &http.Transport{
	// from http.DefaultTransport
	Proxy: http.ProxyFromEnvironment,
	DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	},
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// CreateHTTPClient Create Default HTTP Client
func CreateHTTPClient(dnsServer string) *http.Client {
	dialer.Resolver = CustomDNSResolver(dnsServer)
	// SkipVerfiry
	defaultTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: defaultTransport,
	}
}

// CreateNoProxyHTTPClient Create NoProxy HTTP Client
func CreateNoProxyHTTPClient(network string, dnsServer string) *http.Client {
	dialer.Resolver = CustomDNSResolver(dnsServer)
	if network == "tcp6" {
		var noProxyTcp6Transport = &http.Transport{
			// no proxy
			// DisableKeepAlives
			DisableKeepAlives: true,
			// tcp6
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp6", address)
			},
			// from http.DefaultTransport
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		// SkipVerfiry
		noProxyTcp6Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		return &http.Client{
			Timeout:   30 * time.Second,
			Transport: noProxyTcp6Transport,
		}
	}
	var noProxyTcp4Transport = &http.Transport{
		// no proxy
		// DisableKeepAlives
		DisableKeepAlives: true,
		// tcp4
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		},
		// from http.DefaultTransport
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// SkipVerfiry
	noProxyTcp4Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: noProxyTcp4Transport,
	}
}

// CreateProxyHTTPClient Create Proxy HTTP Client
func CreateProxyHTTPClient(network string, dnsServer, proxyAddr string) *http.Client {
	dialer.Resolver = CustomDNSResolver(dnsServer)
	if network == "tcp6" {
		var transport = &http.Transport{
			// DisableKeepAlives
			DisableKeepAlives: true,
			// tcp6
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				proxyUrl, err := url.Parse(proxyAddr)
				if err == nil {
					xdetail, err := proxy.FromURL(proxyUrl, proxy.Direct)
					if err == nil {
						return xdetail.Dial("tcp6", address)
					}
				}
				return dialer.DialContext(ctx, "tcp6", address)
			},
			// from http.DefaultTransport
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		// SkipVerfiry
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		return &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		}
	}
	var proxyTcp4Transport = &http.Transport{
		// no proxy
		// DisableKeepAlives
		DisableKeepAlives: true,
		// tcp4
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			proxyUrl, err := url.Parse(proxyAddr)
			if err == nil {
				xdetail, err := proxy.FromURL(proxyUrl, proxy.Direct)
				if err == nil {
					return xdetail.Dial("tcp4", address)
				}
			}
			return dialer.DialContext(ctx, "tcp4", address)
		},
		// from http.DefaultTransport
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// SkipVerfiry
	proxyTcp4Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: proxyTcp4Transport,
	}
}

// GetHTTPResponseOrg 处理HTTP结果，返回byte
func GetHTTPResponseOrg(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		klog.Errorln(err)
		return nil, err
	}

	// 300及以上状态码都算异常
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request error: body=%s code=%d\n", string(body), resp.StatusCode)
	}

	return body, err
}
