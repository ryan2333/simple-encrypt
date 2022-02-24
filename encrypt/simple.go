package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

/*
AES实现的方式:

1.电码本模式（Electronic Codebook Book (ECB)）
2.密码分组链接模式（Cipher Block Chaining (CBC)）
3.计算器模式（Counter (CTR)）
4.密码反馈模式（Cipher FeedBack (CFB)）
5.输出反馈模式（Output FeedBack (OFB)）
*/

func MakeAesEncrypt(key, orig []byte) (crypt []byte, err error) {
	var (
		block     cipher.Block
		blockMode cipher.BlockMode
	)

	switch len(key) {
	case 16, 24, 32:
		break
	default:
		err = errors.New(fmt.Sprintf("invalid key size %d, must 16,24,32", len(key)))
		return
	}

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	// 创建加密Mode， 此处使用CBC
	blockMode = cipher.NewCBCEncrypter(block, key)

	// 对byte数组进行长度填充
	orig = PKCS7Padding(orig, block.BlockSize())
	crypt = make([]byte, len(orig))
	blockMode.CryptBlocks(crypt, orig)

	return
}

func ParseAesEncrypt(key, crypt []byte) (orig []byte, err error) {
	var (
		block     cipher.Block
		blockMode cipher.BlockMode
	)

	switch len(key) {
	case 16, 24, 32:
		break
	default:
		err = errors.New(fmt.Sprintf("invalid key size %d, must 16,24,32", len(key)))
		return
	}

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	// 创建解密mod
	blockMode = cipher.NewCBCDecrypter(block, key)

	// 解密
	orig = make([]byte, len(crypt))
	blockMode.CryptBlocks(orig, crypt)
	orig = PKCS7UnPadding(orig)
	return
}

func PKCS7Padding(orig []byte, blockSize int) []byte {
	padding := blockSize - (len(orig) % blockSize)
	return append(orig, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func PKCS7UnPadding(orig []byte) []byte {
	padding := int(orig[len(orig)-1])
	return orig[:len(orig)-padding]
}

func MakeDesEncrypt(key, orig []byte) (crypt []byte, err error) {
	var (
		block     cipher.Block
		blockMode cipher.BlockMode
	)

	if len(key) != 8 {
		err = errors.New(fmt.Sprintf("invalid key size %d, must 8", len(key)))
		return
	}

	if block, err = des.NewCipher(key); err != nil {
		return
	}

	blockMode = cipher.NewCBCEncrypter(block, key)

	orig = PKCS7Padding(orig, block.BlockSize())
	crypt = make([]byte, len(orig))
	blockMode.CryptBlocks(crypt, orig)
	return
}

func ParseDesEncrypt(key, crypt []byte) (orig []byte, err error) {
	var (
		block     cipher.Block
		blockMode cipher.BlockMode
	)

	if len(key) != 8 {
		err = errors.New(fmt.Sprintf("invalid key size %d, must 8", len(key)))
		return
	}

	if block, err = des.NewCipher(key); err != nil {
		return
	}

	blockMode = cipher.NewCBCDecrypter(block, key)
	orig = make([]byte, len(crypt))
	blockMode.CryptBlocks(orig, crypt)
	orig = PKCS7UnPadding(orig)

	return
}

func Make3DesEncrypt(key, orig []byte) (crypt []byte, err error) {
	var (
		block     cipher.Block
		blockMode cipher.BlockMode
	)
	// 3des key必须是24位
	if len(key) != 24 {
		err = errors.New(fmt.Sprintf("invalid key size %d, must 24", len(key)))
		return
	}

	if block, err = des.NewTripleDESCipher(key); err != nil {
		return
	}

	blockMode = cipher.NewCBCEncrypter(block, key[:8])
	orig = PKCS7Padding(orig, block.BlockSize())
	crypt = make([]byte, len(orig))
	blockMode.CryptBlocks(crypt, orig)

	return
}

func Parse3DesEncrypt(key, crypt []byte) (orig []byte, err error) {
	var (
		block     cipher.Block
		blockMode cipher.BlockMode
	)

	if len(key) != 24 {
		err = errors.New(fmt.Sprintf("invalid key size %d, must 24", len(key)))
		return
	}

	if block, err = des.NewTripleDESCipher(key); err != nil {
		return
	}

	blockMode = cipher.NewCBCDecrypter(block, key[:8])
	orig = make([]byte, len(crypt))
	blockMode.CryptBlocks(orig, crypt)
	orig = PKCS7UnPadding(orig)

	return
}

func MakeMd5SaltEncrypt(orig []byte) (crypt []byte, err error) {
	return bcrypt.GenerateFromPassword(orig, 0)
}

func MakeXor(key, orig []byte) []byte {
	crypt := make([]byte, len(orig))

	for i := range crypt {
		crypt[i] = orig[i] ^ key[i%len(key)]
	}

	return crypt
}

func MakeBase64StrWithXor(key, orig []byte) string {
	return base64.StdEncoding.EncodeToString(MakeXor(key, orig))
}

func ParseBase64StrWithXor(key []byte, base64Str string) ([]byte, error) {
	orig, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, nil
	}

	return MakeXor(key, orig), nil
}

func MakeBase64StrWithAes(key, orig []byte) (base64Str string, err error) {
	crypt, err := MakeAesEncrypt(key, orig)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(crypt), nil
}

func ParseBase64StrWithAes(key []byte, base64Str string) (orig []byte, err error) {
	crypt, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return
	}
	return ParseAesEncrypt(key, crypt)
}

func MakeBase64StrWithDes(key, orig []byte) (base64Str string, err error) {
	crypt, err := MakeDesEncrypt(key, orig)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(crypt), nil
}

func ParseBase64StrWithDes(key []byte, base64Str string) (orig []byte, err error) {
	crypt, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return
	}
	return ParseDesEncrypt(key, crypt)
}

func MakeBase64StrWith3Des(key, orig []byte) (base64Str string, err error) {
	crypt, err := Make3DesEncrypt(key, orig)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(crypt), nil
}

func ParseBase64StrWith3Des(key []byte, base64Str string) (orig []byte, err error) {
	crypt, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return
	}
	return Parse3DesEncrypt(key, crypt)
}
