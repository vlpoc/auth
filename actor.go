package auth

import "fmt"

func (a *Actor) ActorString() string {
	if a.Authenticator != "" {
		if a.Domain != "" {
			return fmt.Sprintf("%s/%s@%s", a.Name, a.Domain, a.Authenticator)
		} else {
			return fmt.Sprintf("%s@%s", a.Name, a.Authenticator)
		}
	} else {
		if a.Domain != "" {
			return fmt.Sprintf("%s/%s", a.Name, a.Domain)
		} else {
			return fmt.Sprintf("%s", a.Name)
		}
	}
}
