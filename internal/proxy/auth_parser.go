package proxy

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseProxyAuth parses key=value,key=value,... connection string.
func ParseProxyAuth(connStr string) (*ProxyAuth, error) {
	if connStr == "" {
		return &ProxyAuth{}, nil
	}

	auth := &ProxyAuth{}
	pairs := strings.Split(connStr, ",")

	var lastKey string

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		eqIdx := strings.IndexByte(pair, '=')
		var key, rawValue string

		if eqIdx < 0 {
			if lastKey == "" {
				return nil, fmt.Errorf("invalid parameter: %q (expected key=value)", pair)
			}
			key = lastKey
			rawValue = pair
		} else {
			key = strings.ToLower(strings.TrimSpace(pair[:eqIdx]))
			rawValue = pair[eqIdx+1:]
			lastKey = key
		}

		// URL-decode value
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			value = rawValue // use raw value if decoding fails
		}
		value = strings.TrimSpace(value)

		if value == "" {
			continue
		}

		switch key {
		case "country":
			auth.Countries = append(auth.Countries, value)
		case "city":
			auth.Cities = append(auth.Cities, value)
		case "seed":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid seed value: %q", value)
			}
			auth.Seed = n
		case "owned":
			b, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("invalid owned value: %q", value)
			}
			auth.Owned = &b
		case "provider":
			auth.Providers = append(auth.Providers, value)
		case "speed":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid speed value: %q", value)
			}
			auth.MinSpeed = n
		case "multihop":
			b, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("invalid multihop value: %q", value)
			}
			auth.Multihop = b
		default:
			return nil, fmt.Errorf("unknown parameter: %q", key)
		}
	}

	return auth, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean: %q", s)
	}
}
