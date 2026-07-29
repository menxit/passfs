package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultReleaseBaseURL = "https://getpassfs.com/releases"
	maxMetadataBytes      = 1024 * 1024
	maxAssetBytes         = 512 * 1024 * 1024
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

type Release struct {
	Version   string
	Checksums map[string]string
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (client *Client) Latest(ctx context.Context) (Release, error) {
	versionData, err := client.getBounded(ctx, "latest.txt", 128)
	if err != nil {
		return Release{}, fmt.Errorf("read latest passfs version: %w", err)
	}
	version, err := NormalizeVersion(strings.TrimSpace(string(versionData)))
	if err != nil {
		return Release{}, fmt.Errorf("invalid latest passfs version: %w", err)
	}
	checksumData, err := client.getBounded(
		ctx,
		"latest/SHA256SUMS",
		maxMetadataBytes,
	)
	if err != nil {
		return Release{}, fmt.Errorf("read latest passfs checksums: %w", err)
	}
	checksums, err := ParseChecksums(string(checksumData))
	if err != nil {
		return Release{}, err
	}
	return Release{Version: version, Checksums: checksums}, nil
}

func (client *Client) Download(
	ctx context.Context,
	release Release,
	asset string,
	writer io.Writer,
) error {
	if path.Base(asset) != asset || asset == "." || asset == "" {
		return fmt.Errorf("invalid update asset %q", asset)
	}
	expected, ok := release.Checksums[asset]
	if !ok {
		return fmt.Errorf("checksum for %s is unavailable", asset)
	}
	response, err := client.request(ctx, "latest/"+asset)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	hasher := sha256.New()
	limited := io.LimitReader(response.Body, maxAssetBytes+1)
	count, err := io.Copy(io.MultiWriter(writer, hasher), limited)
	if err != nil {
		return fmt.Errorf("download %s: %w", asset, err)
	}
	if count > maxAssetBytes {
		return fmt.Errorf("%s exceeds the maximum update size", asset)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf(
			"checksum mismatch for %s: received %s, expected %s",
			asset,
			actual,
			expected,
		)
	}
	return nil
}

func (client *Client) getBounded(
	ctx context.Context,
	resource string,
	maximum int64,
) ([]byte, error) {
	response, err := client.request(ctx, resource)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("response is too large")
	}
	return data, nil
}

func (client *Client) request(
	ctx context.Context,
	resource string,
) (*http.Response, error) {
	base, err := url.Parse(client.BaseURL + "/")
	if err != nil {
		return nil, err
	}
	reference, err := url.Parse(resource)
	if err != nil {
		return nil, err
	}
	endpoint := base.ResolveReference(reference)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", endpoint, response.Status)
	}
	return response, nil
}

func ParseChecksums(value string) (map[string]string, error) {
	checksums := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid checksum line %q", scanner.Text())
		}
		checksum := strings.ToLower(fields[0])
		if _, err := hex.DecodeString(checksum); err != nil || len(checksum) != sha256.Size*2 {
			return nil, fmt.Errorf("invalid SHA-256 checksum %q", fields[0])
		}
		name := strings.TrimPrefix(fields[1], "*")
		name = strings.TrimPrefix(name, "./")
		if path.Base(name) != name || name == "." || name == "" {
			return nil, fmt.Errorf("invalid checksum asset %q", name)
		}
		if _, duplicate := checksums[name]; duplicate {
			return nil, fmt.Errorf("duplicate checksum for %s", name)
		}
		checksums[name] = checksum
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(checksums) == 0 {
		return nil, errors.New("checksum file is empty")
	}
	return checksums, nil
}

type semanticVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease string
}

func NormalizeVersion(value string) (string, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	parsed, err := parseVersion(value)
	if err != nil {
		return "", err
	}
	result := fmt.Sprintf("%d.%d.%d", parsed.major, parsed.minor, parsed.patch)
	if parsed.prerelease != "" {
		result += "-" + parsed.prerelease
	}
	return result, nil
}

func IsNewer(candidate, current string) (bool, error) {
	candidate, err := NormalizeVersion(candidate)
	if err != nil {
		return false, err
	}
	current, err = NormalizeVersion(current)
	if err != nil {
		return false, err
	}
	left, _ := parseVersion(candidate)
	right, _ := parseVersion(current)
	return compareVersion(left, right) > 0, nil
}

func parseVersion(value string) (semanticVersion, error) {
	var parsed semanticVersion
	core := value
	if separator := strings.IndexByte(core, '+'); separator >= 0 {
		if err := validateVersionIdentifiers(core[separator+1:], false); err != nil {
			return parsed, fmt.Errorf("%q is not a semantic version", value)
		}
		core = core[:separator]
	}
	if separator := strings.IndexByte(core, '-'); separator >= 0 {
		parsed.prerelease = core[separator+1:]
		core = core[:separator]
		if err := validateVersionIdentifiers(parsed.prerelease, true); err != nil {
			return parsed, fmt.Errorf("%q is not a semantic version", value)
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return parsed, fmt.Errorf("%q is not a semantic version", value)
	}
	numbers := []*uint64{&parsed.major, &parsed.minor, &parsed.patch}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return parsed, fmt.Errorf("%q is not a semantic version", value)
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return parsed, fmt.Errorf("%q is not a semantic version", value)
		}
		*numbers[index] = number
	}
	return parsed, nil
}

func validateVersionIdentifiers(value string, rejectNumericLeadingZero bool) error {
	if value == "" {
		return errors.New("empty version identifier")
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return errors.New("empty version identifier")
		}
		numeric := true
		for _, character := range identifier {
			if character >= '0' && character <= '9' {
				continue
			}
			numeric = false
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				character != '-' {
				return errors.New("invalid version identifier")
			}
		}
		if rejectNumericLeadingZero && numeric &&
			len(identifier) > 1 && identifier[0] == '0' {
			return errors.New("numeric version identifier has a leading zero")
		}
	}
	return nil
}

func compareVersion(left, right semanticVersion) int {
	for _, values := range [][2]uint64{
		{left.major, right.major},
		{left.minor, right.minor},
		{left.patch, right.patch},
	} {
		switch {
		case values[0] < values[1]:
			return -1
		case values[0] > values[1]:
			return 1
		}
	}
	switch {
	case left.prerelease == right.prerelease:
		return 0
	case left.prerelease == "":
		return 1
	case right.prerelease == "":
		return -1
	default:
		return comparePrerelease(left.prerelease, right.prerelease)
	}
}

func comparePrerelease(left, right string) int {
	leftIdentifiers := strings.Split(left, ".")
	rightIdentifiers := strings.Split(right, ".")
	count := min(len(leftIdentifiers), len(rightIdentifiers))
	for index := 0; index < count; index++ {
		leftValue := leftIdentifiers[index]
		rightValue := rightIdentifiers[index]
		if leftValue == rightValue {
			continue
		}
		leftNumber, leftErr := strconv.ParseUint(leftValue, 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightValue, 10, 64)
		switch {
		case leftErr == nil && rightErr == nil:
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		case leftErr == nil:
			return -1
		case rightErr == nil:
			return 1
		default:
			return strings.Compare(leftValue, rightValue)
		}
	}
	switch {
	case len(leftIdentifiers) < len(rightIdentifiers):
		return -1
	case len(leftIdentifiers) > len(rightIdentifiers):
		return 1
	default:
		return 0
	}
}
