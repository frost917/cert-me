package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const trustedProxyCIDRsEnv = "CERT_ME_TRUSTED_PROXY_CIDRS"

// LoadTrustedProxyCIDRs reads the optional, comma-separated trusted proxy
// ranges. It is deliberately separate from LoadFrom so database-only CLI
// commands do not depend on HTTP ingress configuration.
func LoadTrustedProxyCIDRs(lookup Lookup) ([]netip.Prefix, error) {
	if lookup == nil {
		return nil, errors.New("config: environment lookup function is required")
	}
	raw, present := lookup(trustedProxyCIDRsEnv)
	if !present || raw == "" {
		return nil, nil
	}
	if len(raw) > 16*1024 {
		return nil, fmt.Errorf("config: %s exceeds the maximum length", trustedProxyCIDRsEnv)
	}

	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("config: %s contains an empty CIDR", trustedProxyCIDRsEnv)
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil || !prefix.IsValid() || prefix.Addr().Zone() != "" {
			return nil, fmt.Errorf("config: %s contains an invalid CIDR", trustedProxyCIDRsEnv)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("config: %s contains an invalid IPv4-mapped CIDR", trustedProxyCIDRsEnv)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

// LoadTrustedProxyCIDRsFromEnv reads CERT_ME_TRUSTED_PROXY_CIDRS from the
// process environment. An unset value means no proxy is trusted.
func LoadTrustedProxyCIDRsFromEnv() ([]netip.Prefix, error) {
	return LoadTrustedProxyCIDRs(os.LookupEnv)
}
