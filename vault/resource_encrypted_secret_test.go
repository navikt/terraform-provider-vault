package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"log"
)

const dataJson = `{
    "hello": "world"
}`

func TestResourceEncryptedSecret_initial(t *testing.T) {
	_, privateKeyPath, passfilePath := getTestPublicAndPrivateKeysAndPassfilePaths(t)

	privateKey, err := readPrivateKeyFromPath(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	passfileContent, err := readPassfileFromPathAndDecrypt(privateKey, passfilePath)

	if err != nil {
		log.Fatal(err)
	}

	path := acctest.RandomWithPrefix("secret/encrypted_test")
	base64EncryptedValue, err := encryptValueAndConvertToBase64(dataJson, passfileContent)
	if err != nil {
		log.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccVaultEncryptedSecretCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceEncryptedSecret_initialConfig(path, base64EncryptedValue),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"path", path),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_data_json", base64EncryptedValue),
				),
			},
		},
	})
}

func TestResourceEncryptedSecret_updated(t *testing.T) {
	_, privateKeyPath, passfilePath := getTestPublicAndPrivateKeysAndPassfilePaths(t)

	privateKey, err := readPrivateKeyFromPath(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	passfileContent, err := readPassfileFromPathAndDecrypt(privateKey, passfilePath)

	if err != nil {
		log.Fatal(err)
	}

	path := acctest.RandomWithPrefix("secret/encrypted_test")
	oldBase64EncryptedValue, err := encryptValueAndConvertToBase64(dataJson, passfileContent)
	if err != nil {
		log.Fatal(err)
	}

	newBase64EncryptedValue, err := encryptValueAndConvertToBase64(dataJson, passfileContent)
	if err != nil {
		log.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccVaultEncryptedSecretCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceEncryptedSecret_initialConfig(path, oldBase64EncryptedValue),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"path", path),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_data_json", oldBase64EncryptedValue),
				),
			},
			{
				Config: testResourceEncryptedSecret_initialConfig(path, newBase64EncryptedValue),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"path", path),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_data_json", newBase64EncryptedValue),
				),
			},
		},
	})
}

func testAccVaultEncryptedSecretCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*EncryptedClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_encrypted_secret" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for vault encrypted secret %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("vault encrypted secret %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testResourceEncryptedSecret_initialConfig(path, base64Value string) string {
	return fmt.Sprintf(`
resource "vault_encrypted_secret" "test" {
    path = "%s"
    encrypted_data_json = "%s"
}`, path, base64Value)
}

func testResourceEncryptedSecret_initialCheck(expectedPath, dataJsonKey, dataJsonValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_encrypted_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}
		if path != expectedPath {
			return fmt.Errorf("unexpected secret path")
		}

		client := testProvider.Meta().(*EncryptedClient)
		secret, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		if got := secret.Data[dataJsonKey]; got != dataJsonValue {
			return fmt.Errorf("'%s' data is %v; want %q", dataJsonKey, got, dataJsonValue)
		}

		return nil
	}
}
