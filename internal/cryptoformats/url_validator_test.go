package cryptoformats

import (
	"context"
	"errors"
	"testing"
)

func TestURLValidatorHostGrammar(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "localhost", url: "https://localhost"},
		{name: "single label DNS", url: "https://cert"},
		{name: "trailing DNS dot", url: "https://localhost."},
		{name: "mixed case DNS and explicit default port", url: "https://Service.Example.:443/healthz"},
		{name: "valid IPv4 and non-default port", url: "https://192.0.2.1:8443/healthz"},
		{name: "bracketed IPv6", url: "https://[2001:db8::1]:8443/healthz"},
		{name: "syntactic DNS without resolution", url: "https://service.example.invalid"},
		{name: "underscore in DNS label", url: "https://cert_me.example", wantErr: true},
		{name: "ambiguous numeric host", url: "https://123.456", wantErr: true},
		{name: "ambiguous shortened IPv4", url: "https://127.1", wantErr: true},
		{name: "ambiguous zero-padded IPv4", url: "https://192.168.001.001", wantErr: true},
		{name: "bracketed IPv4", url: "https://[127.0.0.1]", wantErr: true},
		{name: "unbracketed IPv6", url: "https://2001:db8::1", wantErr: true},
		{name: "IPv6 zone identifier", url: "https://[fe80::1%25eth0]", wantErr: true},
		{name: "Unicode DNS label", url: "https://café.example", wantErr: true},
		{name: "DNS label starts with hyphen", url: "https://-cert.example", wantErr: true},
		{name: "DNS label ends with hyphen", url: "https://cert-.example", wantErr: true},
		{name: "empty DNS label", url: "https://cert..example", wantErr: true},
		{name: "empty port", url: "https://cert.example:", wantErr: true},
		{name: "zero port", url: "https://cert.example:0", wantErr: true},
		{name: "port out of range", url: "https://cert.example:65536", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (URLValidator{}).Validate(context.Background(), tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate(%q) error = %v, wantErr %t", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestURLValidatorHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := (URLValidator{}).Validate(ctx, "https://service.example.invalid")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Validate() error = %v, want context.Canceled", err)
	}
}
