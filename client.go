package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrBadHandshake is returned when the server response to opening handshake is
// invalid.
var ErrBadHandshake = errors.New("websocket: bad handshake")

// NewClient creates a new client connection using the given net connection.
// The URL u specifies the host and request URI. Use requestHeader to specify
// the origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies
// (Cookie). Use the response.Header to get the selected subprotocol
// (Sec-WebSocket-Protocol) and cookies (Set-Cookie).
//
// If the WebSocket handshake fails, ErrBadHandshake is returned along with a
// non-nil *http.Response so that callers can handle redirects, authentication,
// etc.
func NewClient(netConn net.Conn, host, path string, requestHeader http.Header, readBufSize, writeBufSize int) (c *Conn, response *http.Response, err error) {
	challengeKey, err := generateChallengeKey()
	if err != nil {
		return nil, nil, err
	}
	acceptKey := computeAcceptKey(challengeKey)

	c = newConn(netConn, false, readBufSize, writeBufSize)
	p := c.writeBuf[:0]
	p = append(p, "GET "...)
	p = append(p, path...)
	p = append(p, " HTTP/1.1\r\nHost: "...)
	p = append(p, host...)
	// "Upgrade" is capitalized for servers that do not use case insensitive
	// comparisons on header tokens.
	p = append(p, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "...)
	p = append(p, challengeKey...)
	p = append(p, "\r\n"...)
	for k, vs := range requestHeader {
		for _, v := range vs {
			p = append(p, k...)
			p = append(p, ": "...)
			p = append(p, v...)
			p = append(p, "\r\n"...)
		}
	}
	p = append(p, "\r\n"...)

	if _, err := netConn.Write(p); err != nil {
		return nil, nil, err
	}

	resp, err := http.ReadResponse(c.br, &http.Request{Method: "GET", URL: u})
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 101 ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!strings.EqualFold(resp.Header.Get("Connection"), "upgrade") ||
		resp.Header.Get("Sec-Websocket-Accept") != acceptKey {
		return nil, resp, ErrBadHandshake
	}
	c.subprotocol = resp.Header.Get("Sec-Websocket-Protocol")
	return c, resp, nil
}

// A Dialer contains options for connecting to WebSocket server.
type Dialer struct {
	// NetDial specifies the dial function for creating TCP connections. If
	// NetDial is nil, net.Dial is used.
	NetDial func(network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// Input and output buffer sizes. If the buffer size is zero, then a
	// default value of 4096 is used.
	ReadBufferSize, WriteBufferSize int

	// Subprotocols specifies the client's requested subprotocols.
	Subprotocols []string
}

var errMalformedURL = errors.New("malformed ws or wss URL")

// s 应该是 ws+unix:///var/run/docker.sock/path
func parseURL(s string) (string, string) {
	var host, path string
	switch {
	case strings.HasPrefix(s, "ws://"):
		s = s[len("ws://"):]
	case strings.HasPrefix(s, "ws+unix://"):
		s = s[len("ws+unix://"):]
	}
	if strings.HasPrefix(s, config.Docker.Endpoint) {
		path = s[len(config.Docker.Endpoint):]
		host = config.Docker.Endpoint
	}
	return host, path
}

// DefaultDialer is a dialer with all fields set to the default zero values.
var DefaultDialer *Dialer

// Dial creates a new client connection. Use requestHeader to specify the
// origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies (Cookie).
// Use the response.Header to get the selected subprotocol
// (Sec-WebSocket-Protocol) and cookies (Set-Cookie).
//
// If the WebSocket handshake fails, ErrBadHandshake is returned along with a
// non-nil *http.Response so that callers can handle redirects, authentication,
// etc.
func (d *Dialer) Dial(network, urlStr string, requestHeader http.Header) (*Conn, *http.Response, error) {
	host, path := parseURL(urlStr)

	if d == nil {
		d = &Dialer{}
	}

	var deadline time.Time
	if d.HandshakeTimeout != 0 {
		deadline = time.Now().Add(d.HandshakeTimeout)
	}

	netDial := d.NetDial
	if netDial == nil {
		netDialer := &net.Dialer{Deadline: deadline}
		netDial = netDialer.Dial
	}

	netConn, err := netDial("unix", host)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		if netConn != nil {
			netConn.Close()
		}
	}()

	if err := netConn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}

	readBufferSize := d.ReadBufferSize
	if readBufferSize == 0 {
		readBufferSize = 4096
	}

	writeBufferSize := d.WriteBufferSize
	if writeBufferSize == 0 {
		writeBufferSize = 4096
	}

	if len(d.Subprotocols) > 0 {
		h := http.Header{}
		for k, v := range requestHeader {
			h[k] = v
		}
		h.Set("Sec-Websocket-Protocol", strings.Join(d.Subprotocols, ", "))
		requestHeader = h
	}

	conn, resp, err := NewClient(netConn, host, path, requestHeader, readBufferSize, writeBufferSize)
	if err != nil {
		return nil, resp, err
	}

	netConn.SetDeadline(time.Time{})
	netConn = nil // to avoid close in defer.
	return conn, resp, nil
}
