package vault

import (
	"fmt"
	"strings"
)

type oktaUser struct {
	Username string
	Groups   []string
	Policies []string
}

type oktaGroup struct {
	Name     string
	Policies []string
}

func isOktaUserPresent(client *EncryptedClient, path, username string) (bool, error) {
	secret, err := client.Logical().Read(oktaUserEndpoint(path, username))
	if err != nil {
		return false, err
	}

	return secret != nil, err
}

func listOktaUsers(client *EncryptedClient, path string) ([]string, error) {
	secret, err := client.Logical().List(oktaUserEndpoint(path, ""))
	if err != nil {
		return []string{}, err
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	if v, ok := secret.Data["keys"]; ok {
		return toStringArray(v.([]interface{})), nil
	}

	return []string{}, nil
}

func readOktaUser(client *EncryptedClient, path string, username string) (*oktaUser, error) {
	secret, err := client.Logical().Read(oktaUserEndpoint(path, username))

	if err != nil {
		return nil, err
	}

	return &oktaUser{
		Username: username,
		Groups:   toStringArray(secret.Data["groups"].([]interface{})),
		Policies: toStringArray(secret.Data["policies"].([]interface{})),
	}, nil
}

func updateOktaUser(client *EncryptedClient, path string, user oktaUser) error {
	_, err := client.Logical().Write(oktaUserEndpoint(path, user.Username), map[string]interface{}{
		"groups":   strings.Join(user.Groups, ","),
		"policies": strings.Join(user.Policies, ","),
	})

	return err
}

func deleteOktaUser(client *EncryptedClient, path, username string) error {
	_, err := client.Logical().Delete(oktaUserEndpoint(path, username))
	return err
}

func isOktaAuthBackendPresent(client *EncryptedClient, path string) (bool, error) {
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return false, fmt.Errorf("error reading from Vault: %s", err)
	}

	configuredPath := path + "/"

	for authBackendPath, auth := range auths {

		if auth.Type == "okta" && authBackendPath == configuredPath {
			return true, nil
		}
	}

	return false, nil
}

func isOktaGroupPresent(client *EncryptedClient, path, name string) (bool, error) {
	secret, err := client.Logical().Read(oktaGroupEndpoint(path, name))
	if err != nil {
		return false, err
	}

	return secret != nil, err
}

func listOktaGroups(client *EncryptedClient, path string) ([]string, error) {
	secret, err := client.Logical().List(oktaGroupEndpoint(path, ""))
	if err != nil {
		return []string{}, err
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	if v, ok := secret.Data["keys"]; ok {
		return toStringArray(v.([]interface{})), nil
	}

	return []string{}, nil
}

func readOktaGroup(client *EncryptedClient, path string, name string) (*oktaGroup, error) {
	secret, err := client.Logical().Read(oktaGroupEndpoint(path, name))

	if err != nil {
		return nil, err
	}

	return &oktaGroup{
		Name:     name,
		Policies: toStringArray(secret.Data["policies"].([]interface{})),
	}, nil
}

func updateOktaGroup(client *EncryptedClient, path string, group oktaGroup) error {
	_, err := client.Logical().Write(oktaGroupEndpoint(path, group.Name), map[string]interface{}{
		"policies": strings.Join(group.Policies, ","),
	})

	return err
}

func deleteOktaGroup(client *EncryptedClient, path, name string) error {
	_, err := client.Logical().Delete(oktaGroupEndpoint(path, name))
	return err
}

func oktaConfigEndpoint(path string) string {
	return fmt.Sprintf("/auth/%s/config", path)
}

func oktaUserEndpoint(path, username string) string {
	return fmt.Sprintf("/auth/%s/users/%s", path, username)
}

func oktaGroupEndpoint(path, groupName string) string {
	return fmt.Sprintf("/auth/%s/groups/%s", path, groupName)
}
