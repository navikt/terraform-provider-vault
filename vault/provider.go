package vault

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/hashicorp/terraform/helper/logging"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"encoding/base64"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_ADDR", nil),
				Description: "URL of the root of the target Vault server.",
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_TOKEN", ""),
				Description: "Token to use to authenticate to Vault.",
			},
			"public_key_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_PUBLIC_KEY_PATH", ""),
				Description: "Path to public key used to encrypt `encrypted_passfile_path`.",
			},
			"private_key_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_PRIVATE_KEY_PATH", ""),
				Description: "Path to private key used to decrypt `encrypted_passfile_path`.",
			},
			"encrypted_passfile_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_ENCRYPTED_PASSFILE_PATH", ""),
				Description: "Path to the passfile encrypted using `public_key_path` and encoded using base64.",
			},
			"ca_cert_file": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CACERT", ""),
				Description: "Path to a CA certificate file to validate the server's certificate.",
			},
			"ca_cert_dir": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CAPATH", ""),
				Description: "Path to directory containing CA certificate files to validate the server's certificate.",
			},
			"client_auth": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Client authentication credentials.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cert_file": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("VAULT_CLIENT_CERT", ""),
							Description: "Path to a file containing the client certificate.",
						},
						"key_file": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("VAULT_CLIENT_KEY", ""),
							Description: "Path to a file containing the private key that the certificate was issued for.",
						},
					},
				},
			},
			"skip_tls_verify": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_SKIP_VERIFY", ""),
				Description: "Set this to true only if the target Vault server is an insecure development instance.",
			},
			"max_lease_ttl_seconds": {
				Type:     schema.TypeInt,
				Optional: true,

				// Default is 20min, which is intended to be enough time for
				// a reasonable Terraform run can complete but not
				// significantly longer, so that any leases are revoked shortly
				// after Terraform has finished running.
				DefaultFunc: schema.EnvDefaultFunc("TERRAFORM_VAULT_MAX_TTL", 1200),

				Description: "Maximum TTL for secret leases requested by this provider",
			},
		},

		ConfigureFunc: providerConfigure,

		DataSourcesMap: map[string]*schema.Resource{
			"vault_approle_auth_backend_role_id":   approleAuthBackendRoleIDDataSource(),
			"vault_kubernetes_auth_backend_config": kubernetesAuthBackendConfigDataSource(),
			"vault_kubernetes_auth_backend_role":   kubernetesAuthBackendRoleDataSource(),
			"vault_aws_access_credentials":         awsAccessCredentialsDataSource(),
			"vault_generic_secret":                 genericSecretDataSource(),
		},

		ResourcesMap: map[string]*schema.Resource{
			"vault_approle_auth_backend_login":          approleAuthBackendLoginResource(),
			"vault_approle_auth_backend_role":           approleAuthBackendRoleResource(),
			"vault_approle_auth_backend_role_secret_id": approleAuthBackendRoleSecretIDResource(),
			"vault_auth_backend":                        authBackendResource(),
			"vault_aws_auth_backend_cert":               awsAuthBackendCertResource(),
			"vault_aws_auth_backend_client":             awsAuthBackendClientResource(),
			"vault_aws_auth_backend_identity_whitelist": awsAuthBackendIdentityWhitelistResource(),
			"vault_aws_auth_backend_login":              awsAuthBackendLoginResource(),
			"vault_aws_auth_backend_role":               awsAuthBackendRoleResource(),
			"vault_aws_auth_backend_role_tag":           awsAuthBackendRoleTagResource(),
			"vault_aws_auth_backend_sts_role":           awsAuthBackendSTSRoleResource(),
			"vault_aws_secret_backend":                  awsSecretBackendResource(),
			"vault_aws_secret_backend_role":             awsSecretBackendRoleResource(),
			"vault_database_secret_backend_connection":  databaseSecretBackendConnectionResource(),
			"vault_database_secret_backend_role":        databaseSecretBackendRoleResource(),
			"vault_generic_secret":                      genericSecretResource(),
			"vault_encrypted_secret":                    encryptedSecretResource(),
			"vault_kubernetes_auth_backend_config":      kubernetesAuthBackendConfigResource(),
			"vault_kubernetes_auth_backend_role":        kubernetesAuthBackendRoleResource(),
			"vault_okta_auth_backend":                   oktaAuthBackendResource(),
			"vault_okta_auth_backend_user":              oktaAuthBackendUserResource(),
			"vault_okta_auth_backend_group":             oktaAuthBackendGroupResource(),
			"vault_policy":                              policyResource(),
			"vault_mount":                               mountResource(),
		},
	}
}

type EncryptedClient struct {
	api.Client
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	passfileContent string
}

func NewEncryptedClient(client *api.Client, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, passfileContent string) *EncryptedClient {
	return &EncryptedClient{
		*client,
		publicKey,
		privateKey,
		passfileContent,
	}
}

func readPublicKeyFromFilePath(publicKeyPath string) (*rsa.PublicKey, error) {
	publicKeyContent, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read contents of public_key at public_key_path: %s. Err: %s", publicKeyPath, err)
	}
	block, _ := pem.Decode(publicKeyContent)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf("unable to parse PEM public key. Err: %s", err)
	}
	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("unsupported type of public key")
	}
}

func readPrivateKeyFromPath(privateKeyPath string) (*rsa.PrivateKey, error) {
	privateKeyContent, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read contents of private_key at private_key_path: %s. Err: %s", privateKeyPath, err)
	}

	block, _ := pem.Decode(privateKeyContent)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PKCS1 private key. Err: %s", err)
	}

	return key, nil
}

func readPassfileFromPathAndDecrypt(privateKey *rsa.PrivateKey, passfilePath string) (string, error) {
	encryptedPassfileContent, err := ioutil.ReadFile(passfilePath)
	if err != nil {
		return "", fmt.Errorf("unable to read contents of passfile at encrypted_passfile_path: %s. Err: %s", passfilePath, err)
	}
	base64PassfileContent, err := decryptBase64PassfileContent(privateKey, string(encryptedPassfileContent))
	if err != nil {
		return "", err
	}
	passfileContent, err := base64.StdEncoding.DecodeString(base64PassfileContent)
	if err != nil {
		return "", fmt.Errorf("unable to decode base64 passfile content. Err: %s", passfileContent)
	}

	return strings.TrimSpace(string(passfileContent)), nil
}


func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := api.DefaultConfig()
	config.Address = d.Get("address").(string)

	clientAuthI := d.Get("client_auth").([]interface{})
	if len(clientAuthI) > 1 {
		return nil, fmt.Errorf("client_auth block may appear only once")
	}

	clientAuthCert := ""
	clientAuthKey := ""
	if len(clientAuthI) == 1 {
		clientAuth := clientAuthI[0].(map[string]interface{})
		clientAuthCert = clientAuth["cert_file"].(string)
		clientAuthKey = clientAuth["key_file"].(string)
	}

	err := config.ConfigureTLS(&api.TLSConfig{
		CACert:   d.Get("ca_cert_file").(string),
		CAPath:   d.Get("ca_cert_dir").(string),
		Insecure: d.Get("skip_tls_verify").(bool),

		ClientCert: clientAuthCert,
		ClientKey:  clientAuthKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS for Vault API: %s", err)
	}

	config.HttpClient.Transport = logging.NewTransport("Vault", config.HttpClient.Transport)

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure Vault API: %s", err)
	}

	token := d.Get("token").(string)
	if token == "" {
		// Use the vault CLI's token, if present.
		homePath, err := homedir.Dir()
		if err != nil {
			return nil, fmt.Errorf("Can't find home directory when looking for ~/.vault-token: %s", err)
		}
		tokenBytes, err := ioutil.ReadFile(homePath + "/.vault-token")
		if err != nil {
			return nil, fmt.Errorf("No vault token found: %s", err)
		}

		token = strings.TrimSpace(string(tokenBytes))
	}

	var publicKey *rsa.PublicKey
	publicKeyPathTypeless := d.Get("public_key_path")
	switch publicKeyPathTypeless.(type) {
	case string:
		publicKeyPath := publicKeyPathTypeless.(string)
		if publicKeyPath != "" {
			key, err := readPublicKeyFromFilePath(publicKeyPath)
			if err != nil {
				return nil, err
			}

			publicKey = key
		}
	default:
		return nil, fmt.Errorf("non-string public_key_path")
	}

	var privateKey *rsa.PrivateKey
	privateKeyPathTypeless := d.Get("private_key_path")
	switch privateKeyPathTypeless.(type) {
	case string:
		privateKeyPath := privateKeyPathTypeless.(string)
		if privateKeyPath != "" {
			key, err := readPrivateKeyFromPath(privateKeyPath)
			if err != nil {
				return nil, err
			}

			privateKey = key
		}
	default:
		return nil, fmt.Errorf("non-string private_key_path")
	}

	var passfileContent string
	passfilePathTypeless := d.Get("encrypted_passfile_path")
	switch passfilePathTypeless.(type) {
	case string:
		passfilePath := passfilePathTypeless.(string)
		passfileContent, err = readPassfileFromPathAndDecrypt(privateKey, passfilePath)
		if err != nil {
			return nil ,err
		}
	default:
		return nil, fmt.Errorf("non-string private_key_path")
	}

	// In order to enforce our relatively-short lease TTL, we derive a
	// temporary child token that inherits all of the policies of the
	// token we were given but expires after max_lease_ttl_seconds.
	//
	// The intent here is that Terraform will need to re-fetch any
	// secrets on each run and so we limit the exposure risk of secrets
	// that end up stored in the Terraform state, assuming that they are
	// credentials that Vault is able to revoke.
	//
	// Caution is still required with state files since not all secrets
	// can explicitly be revoked, and this limited scope won't apply to
	// any secrets that are *written* by Terraform to Vault.

	client.SetToken(token)
	renewable := false
	childTokenLease, err := client.Auth().Token().Create(&api.TokenCreateRequest{
		DisplayName:    "terraform",
		TTL:            fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		ExplicitMaxTTL: fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		Renewable:      &renewable,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create limited child token: %s", err)
	}

	childToken := childTokenLease.Auth.ClientToken
	policies := childTokenLease.Auth.Policies

	log.Printf("[INFO] Using Vault token with the following policies: %s", strings.Join(policies, ", "))

	client.SetToken(childToken)

	// TODO: Add validation and error messages when either only
	// a public or private keys are provided.

	if publicKey == nil || privateKey == nil || passfileContent == "" {
		return nil, errors.New("not all of public_key_path, private_key_path and encrypted_passfile_path are provided")
	}

	return NewEncryptedClient(client, publicKey, privateKey, passfileContent), nil
}
