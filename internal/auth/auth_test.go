package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "Valid APIKey header",
			headers: func() http.Header { h := http.Header{}; h.Set("Authorization", "ApiKey 123456789"); return h }(),
			want:    "123456789",
			wantErr: nil,
		},
		{
			name:    "Missing Authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization header - Missing API key",
			headers: func() http.Header { h := http.Header{}; h.Set("Authorization", "ApiKey"); return h }(),
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed Authorization header - Different scheme",
			headers: func() http.Header { h := http.Header{}; h.Set("Authorization", "Bearer 123456789"); return h }(),
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed Authorization header - No space",
			headers: func() http.Header { h := http.Header{}; h.Set("Authorization", "ApiKey123456789"); return h }(),
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}
