package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"crypto/rand"
	"encoding/base64"
	"github.com/hashicorp/terraform/helper/schema"
	"strings"
	"crypto/aes"
	"io"
	"crypto/cipher"
	"crypto/rsa"
	"errors"
	"bytes"
)

func encryptedSecretResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,
		Create:        encryptedSecretResourceWrite,
		Update:        encryptedSecretResourceWrite,
		Delete:        encryptedSecretResourceDelete,
		Read:          encryptedSecretResourceRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the encrypted secret will be written.",
			},
			"encrypted_data_json": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Encrypted, base64-encoded and JSON-encoded secret data to write.",
				ValidateFunc: ValidateEncryptedDataBase64,
				StateFunc:    func(encryptedDataJsonInterface interface{}) string {
					encryptedDataJson := encryptedDataJsonInterface.(string)
					return strings.TrimSpace(encryptedDataJson)
				},
				Sensitive:    true,
			},
		},
	}
}

func pkcs7Pad(bytesValue []byte, blockSize int) ([]byte, error) {
	if bytesValue == nil || len(bytesValue) == 0 {
		return nil, fmt.Errorf("empty value to pad. Given value: %s", bytesValue)
	}

	if blockSize <= 0 {
		return nil, errors.New("blocksize is invalid. it must be greater than or equal to 1")
	}
	padSize := blockSize - (len(bytesValue) % blockSize)
	if padSize == 0 {
		padSize = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(bytesValue, pad...), nil
}

func pkcs7Unpad(bytesValue []byte, blockSize int) ([]byte, error) {
	if bytesValue == nil || len(bytesValue) == 0 {
		return nil, fmt.Errorf("empty value to unpad. Given value: %s", bytesValue)
	}

	if blockSize <= 0 {
		return nil, errors.New("blocksize is invalid. it must be greater than or equal to 1")
	}

	if len(bytesValue) % blockSize != 0 {
		return nil, fmt.Errorf("value length is invalid. value is probably not properly padded via pkcs7. value length: %d", len(bytesValue))
	}

	padSize := int(bytesValue[len(bytesValue)-1])

	pad := bytesValue[len(bytesValue)-padSize:]
	for _, padByte := range pad {
		if padByte != byte(padSize) {
			return nil, errors.New("invalid padding")
		}
	}

	return bytesValue[:len(bytesValue)-padSize], nil
}

func encryptValueAndConvertToBase64(value string, passfileContent string) (string, error) {
	valueBytes := []byte(value)

	paddedValueBytes, err := pkcs7Pad(valueBytes, aes.BlockSize)
	if err != nil {
		return "", err
	}

	if len(paddedValueBytes)%aes.BlockSize != 0 {
		return "", errors.New("value is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(passfileContent))
	if err != nil {
		return "", fmt.Errorf("unable to create aes cipher. Err: %s", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(paddedValueBytes))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedValueBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptBase64PassfileContent(privateKey *rsa.PrivateKey, base64Value string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return "", fmt.Errorf("unable to decode base64 value: %s. Err: %s", base64Value, err)
	}

	decryptedValue, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	return strings.TrimSpace(string(decryptedValue)), err
}

func decryptBase64Value(passfileContent, base64Value string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return "", fmt.Errorf("unable to decode base64 value: %s. Err: %s", base64Value, err)
	}

	block, err := aes.NewCipher([]byte(passfileContent))
	if err != nil {
		return "", fmt.Errorf("unable to create aes cipher. Err: %s", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("encrypted value is too short. Value: %s", ciphertext)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("encrypted value is not a multiple of the block size. Value: %s", ciphertext)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext, err := pkcs7Unpad(ciphertext, aes.BlockSize)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func ValidateEncryptedDataBase64(dataInterface interface{}, _ string) ([]string, []error) {
	data := dataInterface.(string)
	_, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, []error{err}
	}
	return nil, nil
}

func NormalizeEncryptedDataJSON(configI interface{}) string {
	dataJSON := configI.(string)

	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(dataJSON), &dataMap)
	if err != nil {
		// The validate function should've taken care of this.
		log.Printf("[ERROR] Invalid JSON data in vault_encrypted_secret: %s", err)
		return ""
	}

	ret, err := json.Marshal(dataMap)
	if err != nil {
		// Should never happen.
		log.Printf("[ERROR] Problem normalizing JSON for vault_encrypted_secret: %s", err)
		return dataJSON
	}

	return string(ret)
}

func encryptedSecretResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*EncryptedClient)

	path := d.Get("path").(string)

	var data map[string]interface{}
	encryptedValue := d.Get("encrypted_data_json").(string)
	decryptedValue, err := decryptBase64Value(client.passfileContent, encryptedValue)

	if err != nil {
		return fmt.Errorf("unable to decrypt encrypted value %s. Err: %s", path, err)
	}

	err = json.Unmarshal([]byte(decryptedValue), &data)
	if err != nil {
		return fmt.Errorf("encrypted_data_json %#v syntax error: %s", d.Get("encrypted_data_json"), err)
	}

	log.Printf("[DEBUG] Writing encrypted Vault secret to %s", path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return encryptedSecretResourceRead(d, meta)
}

func encryptedSecretResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*EncryptedClient)

	path := d.Id()

	log.Printf("[DEBUG] Deleting vault_encrypted_secret from %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func encryptedSecretResourceRead(_ *schema.ResourceData, _ interface{}) error {
	// NOTE: Don't read back since,
	// we're using encrypted payload already.
	// Reading it back and storing it would need a re-encryption again,
	// which would result in a diff.
	return nil
}
