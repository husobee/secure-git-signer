package main

import "testing"

func TestIsDevStub(t *testing.T) {
	if !isDevStub([]byte(`{"dev_mode_insecure":"true","nonce":"00"}`)) {
		t.Error("expected dev stub to be detected")
	}
	if isDevStub([]byte("not json at all")) {
		t.Error("raw COSE bytes must not be treated as a dev stub")
	}
	if isDevStub([]byte(`{"module_id":"i-123"}`)) {
		t.Error("a real document must not be treated as a dev stub")
	}
}
