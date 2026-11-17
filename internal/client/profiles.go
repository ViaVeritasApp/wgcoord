package client

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"wgcoord/internal/config"
	"wgcoord/internal/wgctl"
)

// RenameProfile renames a profile, keeping it active if it was.
func RenameProfile(oldName, newName string) error {
	if err := config.ValidProfileName(newName); err != nil {
		return err
	}
	return mutate(false, func(c *config.Config) error {
		_, cc, err := c.Profile(oldName)
		if err != nil {
			return err
		}
		if oldName == newName {
			return nil
		}
		if _, ok := c.Profiles[newName]; ok {
			return fmt.Errorf("profile %q already exists", newName)
		}
		delete(c.Profiles, oldName)
		c.Profiles[newName] = cc
		if c.ActiveProfile == oldName {
			c.ActiveProfile = newName
		}
		return nil
	})
}

// RemoveProfile deletes a profile and its keys and token. The active profile
// is taken down first and nothing is left active. It reports whether the
// profile was the active one.
func RemoveProfile(name string) (wasActive bool, err error) {
	err = mutate(false, func(c *config.Config) error {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("a profile name is required")
		}
		_, cc, err := c.Profile(name)
		if err != nil {
			return err
		}
		if c.ActiveProfile == name {
			wasActive = true
			if err := downProfile(cc); err != nil && !errors.Is(err, wgctl.ErrUnsupported) {
				return fmt.Errorf("close profile %q (%s): %w", name, cc.Interface, err)
			}
			c.ActiveProfile = ""
		}
		delete(c.Profiles, name)
		return nil
	})
	return wasActive, err
}

// ImportProfile copies the client from another wgcoord config file into this
// one as profile name, so a machine joined to several coordinators through
// separate --config files can merge them without re-joining. The source's
// active profile is taken (a pre-profiles file has exactly one). The source
// file is left as it was, and the active profile does not change.
func ImportProfile(name, path string) (*config.ClientConfig, error) {
	if err := config.ValidProfileName(name); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if abs == config.Path() {
		return nil, fmt.Errorf("%s is this machine's own config", abs)
	}
	src, err := config.LoadFile(abs)
	if err != nil {
		return nil, err
	}
	if err := src.AssertClient(); err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	_, cc, err := src.Profile("")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	err = mutate(true, func(c *config.Config) error {
		if _, ok := c.Profiles[name]; ok {
			return fmt.Errorf("profile %q already exists", name)
		}
		for n, p := range c.Profiles {
			if p.PublicKey == cc.PublicKey {
				return fmt.Errorf("%s is already imported as profile %q", abs, n)
			}
		}
		if c.Profiles == nil {
			c.Profiles = map[string]*config.ClientConfig{}
		}
		c.Profiles[name] = cc
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cc, nil
}
