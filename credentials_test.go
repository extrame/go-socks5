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

	if !creds.Valid(ctx, "foo", "bar") {
		t.Fatalf("expect valid")
	}

	if !creds.Valid(ctx, "baz", "") {
		t.Fatalf("expect valid")
	}

	if creds.Valid(ctx, "foo", "") {
		t.Fatalf("expect invalid")
	}
}
