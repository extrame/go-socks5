package socks5

import "golang.org/x/net/context"

// CredentialStore is used to support user/pass authentication
type CredentialStore interface {
	Valid(ctx context.Context, user, password string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(ctx context.Context, user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
