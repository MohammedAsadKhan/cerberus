package strength

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const hibpAPI = "https://api.pwnedpasswords.com/range/%s"

// CheckHIBP checks whether a password has appeared in known breach data
// using the HaveIBeenPwned k-Anonymity API.
//
// How k-Anonymity works:
//   - The password is hashed with SHA-1
//   - Only the first 5 characters of the hash are sent to the API
//   - The API returns all hashes that share that 5-character prefix
//   - The full hash is matched locally — the plaintext password never leaves the machine
//
// Returns the number of times the password has been seen in breach data,
// or 0 if it has not been found. A non-nil error means the API was unreachable.
func CheckHIBP(password string) (int, error) {
	// SHA-1 hash the password
	sum := sha1.Sum([]byte(password))
	hash := fmt.Sprintf("%X", sum)

	prefix := hash[:5]
	suffix := hash[5:]

	// Build request with a reasonable timeout
	client := &http.Client{Timeout: 8 * time.Second}

	url := fmt.Sprintf(hibpAPI, prefix)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to build HIBP request: %w", err)
	}

	// HIBP requires a descriptive User-Agent
	req.Header.Set("User-Agent", "Cerberus-CLI-PasswordAuditor/1.0")
	req.Header.Set("Add-Padding", "true") // Padding mode hides query frequency

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("HIBP API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HIBP API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read HIBP response: %w", err)
	}

	// Response format: HASH_SUFFIX:COUNT per line
	// Match our suffix (case-insensitive) and return the breach count
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		if strings.EqualFold(parts[0], suffix) {
			count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return 0, fmt.Errorf("could not parse breach count: %w", err)
			}
			return count, nil
		}
	}

	// No match found — password is not in breach data
	return 0, nil
}
