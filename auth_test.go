package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActorString(t *testing.T) {
	for _, tt := range []struct {
		actorstr string
		actor    *Actor
	}{
		{"kyle", &Actor{Name: "kyle"}},
		{"kyle/ns", &Actor{Name: "kyle", Namespace: "ns"}},
		{"kyle@test.com", &Actor{Name: "kyle", Domain: "test.com"}},
		{"kyle/ns@test.com", &Actor{Name: "kyle", Namespace: "ns", Domain: "test.com"}},
	} {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.actorstr, tt.actor.String())
		})
	}
}

func TestParseActor(t *testing.T) {
	for _, tt := range []struct {
		actorstr string
		actor    *Actor
		err      bool
	}{
		{"kyle", &Actor{Name: "kyle"}, false},
		{"kyle/ns", &Actor{Name: "kyle", Namespace: "ns"}, false},
		{"kyle@test.com", &Actor{Name: "kyle", Domain: "test.com"}, false},
		{"kyle/ns@test.com", &Actor{Name: "kyle", Namespace: "ns", Domain: "test.com"}, false},
		{"foo bar baz", nil, true},
		{"foo bar baz/ns@test.com", nil, true},
		{"/ns@test.com", nil, true},
		{"@test.com", nil, true},
		{"kyle/@test.com", nil, true},
	} {
		t.Run("", func(t *testing.T) {
			a, err := ParseActor(tt.actorstr)
			if tt.actor != nil {
				if !assert.NotNil(t, a) {
					return
				}
				assert.Equal(t, tt.actor.Name, a.Name)
				assert.Equal(t, tt.actor.Namespace, a.Namespace)
				assert.Equal(t, tt.actor.Domain, a.Domain)
			} else if tt.err {
				assert.Error(t, err)
			}
		})
	}
}
