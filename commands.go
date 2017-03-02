package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/boltdb/bolt"
	"math/big"
	"strings"
)

// cmd (1) + len (1) + username (var) + pubkey (33) = 35+
// cmd (1) + len (1) + username (var) + len (1) + image_name (var) + id (1) + pubkey (33) + signature (64) = 101+
// cmd (1) + len (1) + username (var) + len (1) + image_name (var) + len (1) + tag_name (var) + id (1) + len (1) + payload (var) + signature (64) = 70+

const (
	TYPE_REGISTER_ROOT_KEY  int8 = int8(iota) // 0
	TYPE_DELETE_ROOT_KEY    int8 = int8(iota) // 1
	TYPE_REGISTER_KEY       int8 = int8(iota) // 2
	TYPE_DELETE_KEY         int8 = int8(iota) // 3
	TYPE_REGISTER_SIGNATURE int8 = int8(iota) // 4
	TYPE_DELETE_SIGNATURE   int8 = int8(iota) // 5

	BUCKET_ROOT_KEYS  = "rootKeys"
	BUCKET_KEYS       = "keys"
	BUCKET_SIGNATURES = "signatures"
	BUCKET_META       = "meta"
	BUCKET_COMMANDS   = "commands"
	BUCKET_DATAPACKS  = "datapacks"
)

var (
	ErrSignatureEmpty  = errors.New("Signature cannot be empty")
	ErrSignatureFailed = errors.New("Signature failed to match root key")
	ErrUsernameTaken   = errors.New("Username already taken")
	ErrKeyNotFound     = errors.New("Key not found")
	ErrRootKeyNotFound = errors.New("Root Key not found")
	ErrDigestFormat    = errors.New("Digests should be in the format {crypto func}:{hash}")
)

type PublicKeyCompressed [33]byte

func (pubKey PublicKeyCompressed) String() string {
	return hex.EncodeToString(pubKey[:])
}

type Signature [64]byte

func (signature Signature) String() string {
	return hex.EncodeToString(signature[:])
}

type CommandInterface interface {
	Validate(db *bolt.DB) (bool, error)
	Execute(db *bolt.DB) error
	Bytes() []byte
	BytesForSigning() []byte
}

type Command struct {
	Type     int8
	Username string
}

type RootKeyCommand struct {
	Command
	PublicKeyCompressed PublicKeyCompressed
	Signature           Signature
}

type KeyCommand struct {
	RootKeyCommand
	ImageName string
	KeyId     int8
}

type SignatureCommand struct {
	Command
	ImageName string
	TagName   string
	KeyId     int8
	Digests   []string
	Signature Signature
}

func NewRootKeyCommandFromBytes(data []byte) *RootKeyCommand {
	command := &RootKeyCommand{}

	command.Type = int8(data[0])
	pos := 1

	usernameLength := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	username := make([]byte, usernameLength)
	copy(username, data[pos:pos+usernameLength])
	command.Username = string(username)
	pos += usernameLength

	copy(command.PublicKeyCompressed[:], data[pos:pos+33])
	pos += 33

	if command.Type == TYPE_DELETE_ROOT_KEY {
		copy(command.Signature[:], data[pos:pos+64])
	}

	return command
}

func NewRootKeyCommandFromRootKeyRequest(request *RootKeyRequest, type1 int8) (*RootKeyCommand, error) {
	data := &RootKeyCommand{}
	data.Type = type1
	data.Username = request.Username
	if len(data.Username) == 0 {
		return nil, ErrUsernameEmpty
	}
	publicKeyCompressed, err := hex.DecodeString(request.PublicKeyCompressed)
	if err != nil {
		return nil, err
	}
	if len(publicKeyCompressed) != 33 {
		return nil, ErrPublicKeyLength
	}
	_, err = UnserializePublicKeyCompressed(secp256k1Curve, publicKeyCompressed)
	if err != nil {
		return nil, err
	}
	copy(data.PublicKeyCompressed[:], publicKeyCompressed)

	return data, nil
}

func (command *RootKeyCommand) Bytes() []byte {
	bin := make([]byte, 0)

	// construct username length in bytes
	usernameLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(usernameLength, uint32(len(command.Username)))

	bin = append(bin, byte(command.Type))
	bin = append(bin, usernameLength...)
	bin = append(bin, command.Username...)
	bin = append(bin, command.PublicKeyCompressed[:]...)
	if command.Type == TYPE_DELETE_ROOT_KEY {
		bin = append(bin, command.Signature[:]...)
	}

	return bin
}

func (command *RootKeyCommand) BytesForSigning() []byte {
	signature := command.Signature
	command.Signature = Signature{}
	b := command.Bytes()
	command.Signature = signature
	return b
}

func (command *RootKeyCommand) Validate(db *bolt.DB) (bool, error) {
	err := db.View(func(tx *bolt.Tx) error {
		bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
		existingPubKey := bRootKeys.Get([]byte(command.Username))
		if existingPubKey != nil {
			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			r, _ := big.NewInt(0).SetString(hex.EncodeToString(command.Signature[:32]), 16)
			s, _ := big.NewInt(0).SetString(hex.EncodeToString(command.Signature[32:]), 16)
			verify := ecdsa.Verify(&publicKey, command.BytesForSigning(), r, s)

			if !verify {
				if command.Type == TYPE_REGISTER_ROOT_KEY {
					return ErrUsernameTaken
				} else {
					return ErrSignatureFailed
				}
			}
		} else if command.Type == TYPE_DELETE_ROOT_KEY && existingPubKey == nil {
			return ErrKeyNotFound
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	return true, nil
}

func (command *RootKeyCommand) Execute(db *bolt.DB) error {
	if command.Type == TYPE_REGISTER_ROOT_KEY {
		err := db.Batch(func(tx *bolt.Tx) error {
			bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
			return bRootKeys.Put([]byte(command.Username), command.PublicKeyCompressed[:])
		})
		if err != nil {
			return err
		}

		// TODO: Delete all sub-keys and signatures if key changed
	} else if command.Type == TYPE_DELETE_ROOT_KEY {
		err := db.Batch(func(tx *bolt.Tx) error {
			bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
			return bRootKeys.Delete([]byte(command.Username))
		})
		if err != nil {
			return err
		}

		// TODO: Delete all sub-keys and signatures
	}

	return nil
}

func NewKeyCommandFromBytes(data []byte) *KeyCommand {
	command := &KeyCommand{}

	command.Type = int8(data[0])
	pos := 1

	usernameLength := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	username := make([]byte, usernameLength)
	copy(username, data[pos:pos+usernameLength])
	command.Username = string(username)
	pos += usernameLength

	copy(command.PublicKeyCompressed[:], data[pos:pos+33])
	pos += 33

	imageNameLength := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	imageName := make([]byte, imageNameLength)
	copy(imageName, data[pos:pos+imageNameLength])
	command.ImageName = string(imageName)
	pos += imageNameLength

	command.KeyId = int8(data[pos])
	pos += 1

	copy(command.Signature[:], data[pos:pos+64])

	return command
}

func NewKeyCommandFromKeyRequest(request *KeyRequest, type1 int8) (*KeyCommand, error) {
	data := &KeyCommand{}
	data.Type = type1
	data.Username = request.Username
	if len(data.Username) == 0 {
		return nil, ErrUsernameEmpty
	}
	publicKeyCompressed, err := hex.DecodeString(request.PublicKeyCompressed)
	if err != nil {
		return nil, err
	}
	if len(publicKeyCompressed) != 33 {
		return nil, ErrPublicKeyLength
	}
	_, err = UnserializePublicKeyCompressed(secp256k1Curve, publicKeyCompressed)
	if err != nil {
		return nil, err
	}
	copy(data.PublicKeyCompressed[:], publicKeyCompressed)
	data.ImageName = request.ImageName
	if len(data.ImageName) == 0 {
		return nil, ErrImageNameEmpty
	}
	data.KeyId = request.KeyId

	var setSuccess bool
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D, setSuccess = new(big.Int).SetString(request.PrivateKey, 16)
	if !setSuccess {
		return nil, ErrPrivateKeyInvalid
	}
	privateKey.PublicKey.Curve = secp256k1Curve
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data.BytesForSigning())
	if err != nil {
		return nil, err
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	copy(data.Signature[:], signature)

	return data, nil
}

func (command *KeyCommand) Bytes() []byte {
	bin := make([]byte, 0)

	// construct username length in bytes
	usernameLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(usernameLength, uint32(len(command.Username)))

	// construct image name length in bytes
	imageNameLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(imageNameLength, uint32(len(command.ImageName)))

	bin = append(bin, byte(command.Type))
	bin = append(bin, usernameLength...)
	bin = append(bin, command.Username...)
	bin = append(bin, command.PublicKeyCompressed[:]...)
	bin = append(bin, imageNameLength...)
	bin = append(bin, command.ImageName...)
	bin = append(bin, byte(command.KeyId))
	bin = append(bin, command.Signature[:]...)

	return bin
}

func (command *KeyCommand) BytesForSigning() []byte {
	signature := command.Signature
	command.Signature = Signature{}
	b := command.Bytes()
	command.Signature = signature
	return b
}

func (command *KeyCommand) Validate(db *bolt.DB) (bool, error) {
	var rootPubKey []byte
	err := db.View(func(tx *bolt.Tx) error {
		bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
		rootPubKey = bRootKeys.Get([]byte(command.Username))
		if rootPubKey == nil {
			return ErrRootKeyNotFound
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, rootPubKey)
	if err != nil {
		// TODO: Should I not panic?
		panic(err)
		return false, nil
	}

	emptySignature := Signature{}
	if bytes.Equal(command.Signature[:], emptySignature[:]) {
		return false, ErrSignatureEmpty
	}

	r, _ := big.NewInt(0).SetString(hex.EncodeToString(command.Signature[:32]), 16)
	s, _ := big.NewInt(0).SetString(hex.EncodeToString(command.Signature[32:]), 16)
	verify := ecdsa.Verify(&publicKey, command.BytesForSigning(), r, s)

	if verify {
		if command.Type == TYPE_DELETE_KEY {
			err := db.View(func(tx *bolt.Tx) error {
				bKeys := tx.Bucket([]byte(BUCKET_KEYS))
				bUsername := bKeys.Bucket([]byte(command.Username))
				if bUsername == nil {
					return ErrKeyNotFound
				}
				bImageName := bUsername.Bucket([]byte(command.ImageName))
				if bImageName == nil {
					return ErrKeyNotFound
				}
				existingPubKey := bImageName.Get([]byte{byte(command.KeyId)})
				if existingPubKey == nil {
					return ErrKeyNotFound
				}

				return nil
			})
			if err != nil {
				return false, err
			}

			return true, nil
		} else {
			return true, nil
		}
	} else {
		return false, ErrSignatureFailed
	}

	return false, nil
}

func (command *KeyCommand) Execute(db *bolt.DB) error {
	if command.Type == TYPE_REGISTER_KEY {
		err := db.Batch(func(tx *bolt.Tx) error {
			bKeys := tx.Bucket([]byte(BUCKET_KEYS))
			bUsername, err := bKeys.CreateBucketIfNotExists([]byte(command.Username))
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}
			bImageName, err := bUsername.CreateBucketIfNotExists([]byte(command.ImageName))
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}
			err = bImageName.Put([]byte{byte(command.KeyId)}, command.PublicKeyCompressed[:])
			if err != nil {
				return err
			}

			bMeta, err := bImageName.CreateBucketIfNotExists([]byte(BUCKET_META))
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}
			key := append([]byte("signature_"), byte(command.KeyId))
			err = bMeta.Put(key, command.Signature[:])
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}

		// TODO: Do we need to delete all signatures if key changed?
	} else if command.Type == TYPE_DELETE_KEY {
		err := db.Batch(func(tx *bolt.Tx) error {
			bKeys := tx.Bucket([]byte(BUCKET_KEYS))
			bUsername := bKeys.Bucket([]byte(command.Username))
			if bUsername == nil {
				return ErrKeyNotFound
			}
			bImageName := bUsername.Bucket([]byte(command.ImageName))
			if bImageName == nil {
				return ErrKeyNotFound
			}
			err := bImageName.Delete([]byte{byte(command.KeyId)})
			if err != nil {
				return ErrKeyNotFound
			}

			bMeta := bImageName.Bucket([]byte(BUCKET_META))
			if bMeta != nil {
				key := append([]byte("signature_"), byte(command.KeyId))
				err = bMeta.Delete(key)
				if err != nil {
					return err
				}
			}

			// Delete bucket if no more keys
			if bImageName.Stats().KeyN == 0 {
				err = bUsername.DeleteBucket([]byte(command.ImageName))
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return err
		}

		// TODO: Do we need to delete all signatures if key changed?
	}

	return nil
}

func NewSignatureCommandFromBytes(data []byte) *SignatureCommand {
	command := &SignatureCommand{}

	command.Type = int8(data[0])
	pos := 1

	usernameLength := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	username := make([]byte, usernameLength)
	copy(username, data[pos:pos+usernameLength])
	command.Username = string(username)
	pos += usernameLength

	imageNameLength := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	imageName := make([]byte, imageNameLength)
	copy(imageName, data[pos:pos+imageNameLength])
	command.ImageName = string(imageName)
	pos += imageNameLength

	tagNameLength := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	tagName := make([]byte, tagNameLength)
	copy(tagName, data[pos:pos+tagNameLength])
	command.TagName = string(tagName)
	pos += tagNameLength

	command.KeyId = int8(data[pos])
	pos += 1

	digestsLength := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	digests := make([]string, digestsLength)
	for i := 0; i < digestsLength; i++ {
		cryptoLength := int8(data[pos])
		pos += 1

		crypto := make([]byte, cryptoLength)
		copy(crypto, data[pos:pos+int(cryptoLength)])
		pos += int(cryptoLength)

		hashLength := int8(data[pos])
		pos += 1

		hash := make([]byte, hashLength)
		copy(hash, data[pos:pos+int(hashLength)])
		pos += int(hashLength)

		digests[i] = string(crypto) + ":" + hex.EncodeToString(hash)
	}
	command.Digests = digests

	copy(command.Signature[:], data[pos:pos+64])

	return command
}

func (command *SignatureCommand) Bytes() []byte {
	bin := make([]byte, 0)

	// construct username length in bytes
	usernameLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(usernameLength, uint32(len(command.Username)))

	// construct image name length in bytes
	imageNameLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(imageNameLength, uint32(len(command.ImageName)))

	// construct tag name length in bytes
	tagNameLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(tagNameLength, uint32(len(command.TagName)))

	// construct digestsLength length in bytes
	digestsLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(digestsLength, uint32(len(command.Digests)))

	bin = append(bin, byte(command.Type))
	bin = append(bin, usernameLength...)
	bin = append(bin, command.Username...)
	bin = append(bin, imageNameLength...)
	bin = append(bin, command.ImageName...)
	bin = append(bin, tagNameLength...)
	bin = append(bin, command.TagName...)
	bin = append(bin, byte(command.KeyId))
	bin = append(bin, digestsLength...)
	for i := 0; i < len(command.Digests); i++ {
		split := strings.Split(command.Digests[i], ":")
		if len(split) != 2 {
			panic(ErrDigestFormat)
		}
		hash, err := hex.DecodeString(split[1])
		if err != nil {
			panic(err)
		}
		bin = append(bin, byte(len(split[0])))
		bin = append(bin, split[0]...)
		bin = append(bin, byte(len(hash)))
		bin = append(bin, hash...)
	}
	bin = append(bin, command.Signature[:]...)

	return bin
}

func (command *SignatureCommand) BytesForSigning() []byte {
	signature := command.Signature
	command.Signature = Signature{}
	b := command.Bytes()
	command.Signature = signature
	return b
}

func (command *SignatureCommand) Validate(db *bolt.DB) (bool, error) {
	var pubKey []byte
	err := db.View(func(tx *bolt.Tx) error {
		bKeys := tx.Bucket([]byte(BUCKET_KEYS))
		bUsername := bKeys.Bucket([]byte(command.Username))
		if bUsername == nil {
			return ErrKeyNotFound
		}
		bImageName := bUsername.Bucket([]byte(command.ImageName))
		if bImageName == nil {
			return ErrKeyNotFound
		}
		pubKey = bImageName.Get([]byte{byte(command.KeyId)})
		if pubKey == nil {
			return ErrKeyNotFound
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, pubKey)
	if err != nil {
		// TODO: Should I not panic?
		panic(err)
		return false, nil
	}

	emptySignature := Signature{}
	if bytes.Equal(command.Signature[:], emptySignature[:]) {
		return false, ErrSignatureEmpty
	}

	r, _ := big.NewInt(0).SetString(hex.EncodeToString(command.Signature[:32]), 16)
	s, _ := big.NewInt(0).SetString(hex.EncodeToString(command.Signature[32:]), 16)
	verify := ecdsa.Verify(&publicKey, command.BytesForSigning(), r, s)

	if verify {
		if command.Type == TYPE_DELETE_SIGNATURE {
			err := db.View(func(tx *bolt.Tx) error {
				bSignatures := tx.Bucket([]byte(BUCKET_SIGNATURES))
				bUsername := bSignatures.Bucket([]byte(command.Username))
				if bUsername == nil {
					return ErrSignatureDoesNotExist
				}
				bImage := bUsername.Bucket([]byte(command.ImageName))
				if bImage == nil {
					return ErrSignatureDoesNotExist
				}
				bTag := bImage.Bucket([]byte(command.TagName))
				if bTag == nil {
					return ErrSignatureDoesNotExist
				}

				return nil
			})
			if err != nil {
				return false, err
			}

			return true, nil
		} else {
			return true, nil
		}
	} else {
		return false, ErrSignatureFailed
	}

	return false, nil
}

func (command *SignatureCommand) Execute(db *bolt.DB) error {
	if command.Type == TYPE_REGISTER_SIGNATURE {
		err := db.Batch(func(tx *bolt.Tx) error {
			bSignatures := tx.Bucket([]byte(BUCKET_SIGNATURES))
			bUsername, err := bSignatures.CreateBucketIfNotExists([]byte(command.Username))
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}
			bImage, err := bUsername.CreateBucketIfNotExists([]byte(command.ImageName))
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}
			bImage.DeleteBucket([]byte(command.TagName))
			bTag, err := bImage.CreateBucket([]byte(command.TagName))
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}
			for _, digest := range command.Digests {
				id, _ := bTag.NextSequence()
				bId := make([]byte, 8)
				binary.BigEndian.PutUint64(bId, uint64(id))
				err := bTag.Put(bId, []byte(digest))
				if err != nil {
					return err
				}
			}

			bMeta, err := bTag.CreateBucketIfNotExists([]byte(BUCKET_META))
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}
			err = bMeta.Put([]byte("keyId"), []byte{byte(command.KeyId)})
			if err != nil {
				return err
			}
			err = bMeta.Put([]byte("signature"), command.Signature[:])
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}
	} else if command.Type == TYPE_DELETE_SIGNATURE {
		err := db.Batch(func(tx *bolt.Tx) error {
			bSignatures := tx.Bucket([]byte(BUCKET_SIGNATURES))
			bUsername := bSignatures.Bucket([]byte(command.Username))
			if bUsername == nil {
				return ErrSignatureDoesNotExist
			}
			bImage := bUsername.Bucket([]byte(command.ImageName))
			if bImage == nil {
				return ErrSignatureDoesNotExist
			}
			err := bImage.DeleteBucket([]byte(command.TagName))
			if err != nil {
				return ErrSignatureDoesNotExist
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}
