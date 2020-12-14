package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
)

type AuthMethodCode uint8

const (
	NoAuth       AuthMethodCode = 0
	UserPassAuth AuthMethodCode = 2

	userAuthVersion uint8 = 1
	noAcceptable    uint8 = 255
	authSuccess     uint8 = 0
	authFailure     uint8 = 1
)

func (a AuthMethodCode) String() string {
	switch uint8(a) {
	case 0:
		return "NoAuth"
	case 1:
		return "GSSAPI"
	case 2:
		return "UserPassAuth"
	default:
		return "unknown"
	}
}

var (
	UserAuthFailed  = fmt.Errorf("User authentication failed")
	NoSupportedAuth = "No supported authentication mechanism in %v"
)

// A Request encapsulates authentication state provided
// during negotiation
type AuthContext struct {
	// Provided auth method
	Method AuthMethodCode
	// Payload provided during negotiation.
	// Keys depend on the used auth method.
	// For UserPassauth contains Username
	Payload map[string]string
}

type Authenticator interface {
	Authenticate(context.Context, io.Reader, io.Writer, net.Addr) (context.Context, *AuthContext, error)
	GetCode() AuthMethodCode
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() AuthMethodCode {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(ctx context.Context, reader io.Reader, writer io.Writer, addr net.Addr) (context.Context, *AuthContext, error) {
	_, err := writer.Write([]byte{socks5Version, byte(NoAuth)})
	return ctx, &AuthContext{NoAuth, nil}, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() AuthMethodCode {
	return UserPassAuth
}

func (a UserPassAuthenticator) Authenticate(ctx context.Context, reader io.Reader, writer io.Writer, addr net.Addr) (context.Context, *AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{socks5Version, byte(UserPassAuth)}); err != nil {
		return ctx, nil, err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return ctx, nil, err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return ctx, nil, fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return ctx, nil, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return ctx, nil, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return ctx, nil, err
	}

	// Verify the password
	ctx_, ok := a.Credentials.Valid(ctx, string(user), string(pass), addr)
	if ok {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return ctx_, nil, err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return ctx_, nil, err
		}
		return ctx_, nil, UserAuthFailed
	}

	// Done
	return ctx_, &AuthContext{UserPassAuth, map[string]string{"Username": string(user)}}, nil
}

// authenticate is used to handle connection authentication
func (s *Server) authenticate(ctx context.Context, conn io.Writer, bufConn io.Reader, addr net.Addr) (context.Context, *AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return ctx, nil, fmt.Errorf("Failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			return cator.Authenticate(ctx, bufConn, conn, addr)
		}
	}

	// No usable method found
	return ctx, nil, noAcceptableAuth(conn, methods)
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer, methods []AuthMethodCode) error {
	conn.Write([]byte{socks5Version, noAcceptable})
	return fmt.Errorf(NoSupportedAuth, methods)
}

// readMethods is used to read the number of methods
// and proceeding auth methods
func readMethods(r io.Reader) ([]AuthMethodCode, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]uint8, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	alisedMethods := make([]AuthMethodCode, len(methods))
	for k, v := range methods {
		alisedMethods[k] = AuthMethodCode(v)
	}
	return alisedMethods, err
}
