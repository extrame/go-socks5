package socks5

import (
	"context"
	"testing"
)

func TestStaticCredentials(t *testing.T) {
	ctx := context.Background()

	creds := StaticCredentials{
		"foo": "bar",
		"baz": "",
	}

	if _, ok := creds.Valid(ctx, "foo", "bar", nil); !ok {
		t.Fatalf("expect valid")
	}

	if _, ok := creds.Valid(ctx, "baz", "", nil); !ok {
		t.Fatalf("expect valid")
	}

	if _, ok := creds.Valid(ctx, "foo", "", nil); ok {
		t.Fatalf("expect invalid")
	}
}
