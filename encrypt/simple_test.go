package encrypt

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestMakeAesEncrypt(t *testing.T) {
	key := []byte("hhhhhhhhhhhhhhhh")
	crypt, err := MakeAesEncrypt(key, []byte("pip123"))
	if err != nil {
		t.Errorf("encrypt failed, err: %v", err.Error())
		return
	}
	t.Logf("encry: %s", string(crypt))

	orig, err := ParseAesEncrypt(key, crypt)
	if err != nil {
		t.Errorf("parse failed, err: %s", err.Error())
		return
	}
	t.Log("str: ", string(orig))
}

func TestMakeDesEncrypt(t *testing.T) {
	key := []byte("hhhhhhhh")
	str := "pip2333"
	crypt, err := MakeDesEncrypt(key, []byte(str))
	if err != nil {
		t.Errorf("get des failed, err: %v", err.Error())
		return
	}
	t.Log("crypt: ", string(crypt))

	orig, err := ParseDesEncrypt(key, crypt)
	if err != nil {
		t.Errorf("parse failed, err: %v", err.Error())
		return
	}
	t.Log("orig: ", string(orig))
}

func TestMake3DesEncrypt(t *testing.T) {
	key := []byte("hhhhhhhhhhhhhhhhhhhhhhhh")
	crypt, err := Make3DesEncrypt(key, []byte("pip123456778"))
	if err != nil {
		t.Errorf("encryp failed, err: %v", err.Error())
		return
	}
	t.Log("crypt: ", string(crypt))

	orig, err := Parse3DesEncrypt(key, crypt)
	if err != nil {
		t.Errorf("parse failed, err: %v", err.Error())
		return
	}
	t.Log("orig: ", string(orig))
}

func TestMakeMd5SaltEncrypt(t *testing.T) {
	crypt, err := MakeMd5SaltEncrypt([]byte("pip123123123123"))
	if err != nil {
		t.Errorf("encrypt failed, err: %v", err.Error())
		return
	}
	t.Log("crypt: ", string(crypt))
	if bcrypt.CompareHashAndPassword(crypt, []byte("pip123123123123")) == nil {
		t.Log("success")
	} else {
		t.Error("failed")
	}
}

func TestMakeBase64StrWithAes(t *testing.T) {
	key := []byte("1234567890123456")
	bt, err := MakeBase64StrWithAes(key, []byte("pip123"))
	if err != nil {
		t.Errorf("base crypt failed, err: %v", err.Error())
		return
	}
	t.Log("base aes str: ", string(bt))

	str, err := ParseBase64StrWithAes(key, string(bt))
	if err != nil {
		t.Errorf("base parse failed, err: %v", err.Error())
		return
	}

	t.Log("base aes parse: ", string(str))
}

func TestMakeBase64StrWithDes(t *testing.T) {
	key := []byte("12345678")
	bt, err := MakeBase64StrWithDes(key, []byte("pip123"))
	if err != nil {
		t.Errorf("base crypt failed, err: %v", err.Error())
		return
	}
	t.Log("base des str: ", string(bt))

	str, err := ParseBase64StrWithDes(key, string(bt))
	if err != nil {
		t.Errorf("base parse failed, err: %v", err.Error())
		return
	}

	t.Log("base des parse: ", string(str))
}

func TestMakeBase64StrWith3Des(t *testing.T) {
	key := []byte("123456789012345612345678")
	bt, err := MakeBase64StrWith3Des(key, []byte("pip123"))
	if err != nil {
		t.Errorf("base crypt failed, err: %v", err.Error())
		return
	}
	t.Log("base 3des str: ", string(bt))

	str, err := ParseBase64StrWith3Des(key, string(bt))
	if err != nil {
		t.Errorf("base parse failed, err: %v", err.Error())
		return
	}

	t.Log("base 3des parse: ", string(str))
}

func TestMakeBase64StrWithXor(t *testing.T) {
	key := "xx2233"
	pass := "pip123456"

	hh := MakeBase64StrWithXor([]byte(key), []byte(pass))
	t.Log("encrypt: ", string(hh))

	d, err := ParseBase64StrWithXor([]byte(key), string(hh))
	if err != nil {
		t.Errorf("parse encrypt failed, err: %v", err.Error())
		return
	}
	t.Log("decrypt: ", string(d))
}
