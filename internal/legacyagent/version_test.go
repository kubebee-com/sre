package legacyagent

import "testing"

func TestHasVersionFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "long", args: []string{"--version"}, want: true},
		{name: "short", args: []string{"-version"}, want: true},
		{name: "other flag", args: []string{"-port", "8080"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasVersionFlag(tt.args); got != tt.want {
				t.Fatalf("hasVersionFlag(%v) = %t, want %t", tt.args, got, tt.want)
			}
		})
	}
}
