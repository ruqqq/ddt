package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/boltdb/bolt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/labstack/echo"
	"github.com/ruqqq/blockchainparser/rpc"
	"github.com/ruqqq/carbonchain"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

const DEFAULT_BTC_FEE float64 = 0.00002

var (
	ErrUsernameEmpty         = errors.New("Username cannot be empty")
	ErrNoAccess              = errors.New("Private key has no access")
	ErrPublicKeyLength       = errors.New("Public key (compressed) has to be 33 bytes")
	ErrPrivateKeyInvalid     = errors.New("Private key is invalid")
	ErrImageNameEmpty        = errors.New("ImageName cannot be empty")
	ErrTagNameEmpty          = errors.New("TagName cannot be empty")
	ErrDigestsEmpty          = errors.New("Digests cannot be empty")
	ErrRootKeyDoesNotExist   = errors.New("Root key does not exist")
	ErrKeyDoesNotExist       = errors.New("Key does not exist")
	ErrSignatureDoesNotExist = errors.New("Signature does not exist")
	ErrNameInvalid           = errors.New("Name has to be in the format of {username}/{image name}:{tag name}")
)

const (
	StatusRootKeyDoesNotExist = "ROOT_KEY_MISSING"
	StatusKeyDoesNotExist     = "KEY_MISSING"
	StatusSignatureNotValid   = "SIGNATURE_INVALID"
	StatusSignatureValid      = "SIGNATURE_VALID"
	StatusUnableToVerify      = "UNABLE_TO_VERIFY"
)

type CustomContext struct {
	echo.Context
	BitcoindRpcOptions *rpc.RpcOptions
	Db                 *bolt.DB
}

type CreateKeyPairResponse struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type RawSignatureRequest struct {
	PrivateKey string `json:"privateKey"`
	Message    string `json:"message"`
	MessageHex string `json:"messageHex"`
}

type RawSignatureResponse struct {
	Signature string `json:"signature"`
}

type VerifyRequest struct {
	PublicKey  string `json:"publicKey"`
	Message    string `json:"message"`
	MessageHex string `json:"messageHex"`
	Signature  string `json:"signature"`
}

type VerifyResponse struct {
	Signature string `json:"signature"`
	Verified  bool   `json:"verified"`
}

type RootKeyRequest struct {
	PrivateKey          string `json:"privateKey"`
	Username            string `json:"username"`
	PublicKeyCompressed string `json:"publicKey"`
}

type TxIdResponse struct {
	Txids []string `json:"txIds"`
}

type KeyRequest struct {
	PrivateKey          string `json:"privateKey"`
	Username            string `json:"username"`
	PublicKeyCompressed string `json:"publicKey"`
	ImageName           string `json:"imageName"`
	KeyId               int8   `json:"keyId"`
}

type SignatureRequest struct {
	PrivateKey string   `json:"privateKey"`
	Username   string   `json:"username"`
	ImageName  string   `json:"imageName"`
	TagName    string   `json:"tagName"`
	KeyId      int8     `json:"keyId"`
	Digests    []string `json:"digests"`
}

type GetRootPublicKeyForUserResponse struct {
	PublicKeyCompressed string   `json:"publicKey"`
	Images              []string `json:"images"`
	RegisteredRepo      []string `json:"registeredRepo"`
}

type GetPublicKeysForImageResponse struct {
	PublicKeys map[int]PublicKeyResponse `json:"publicKeys"`
}

type PublicKeyResponse struct {
	PublicKeyCompressed string `json:"publicKey"`
	Signature           string `json:"signature"`
	Status              string `json:"status,omitempty"`
}

type GetSignatureForTagResponse struct {
	Name      string   `json:"name"`
	Hashes    []string `json:"hashes"`
	KeyId     int8     `json:"keyId"`
	Signature string   `json:"signature"`
	Status    string   `json:"status,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

var secp256k1Curve = secp256k1.S256()

func CreateKeyPair(c echo.Context) error {
	privateKey, err := ecdsa.GenerateKey(secp256k1Curve, rand.Reader) // this generates a public & private key pair
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}
	publicKey := privateKey.PublicKey

	return c.JSONPretty(http.StatusOK, CreateKeyPairResponse{
		PrivateKey: hex.EncodeToString(privateKey.D.Bytes()),
		PublicKey:  hex.EncodeToString(SerializePublicKeyCompressed(publicKey)),
	}, "  ")
}

func SignMessage(c echo.Context) error {
	request := new(RawSignatureRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	var setSuccess bool
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D, setSuccess = new(big.Int).SetString(request.PrivateKey, 16)
	if !setSuccess {
		return ShowErrorJSON(c, http.StatusBadRequest, errors.New("Private Key is invalid."))
	}
	privateKey.PublicKey.Curve = secp256k1Curve

	msg := []byte(request.Message)
	if request.MessageHex != "" {
		var err error
		msg, err = hex.DecodeString(request.MessageHex)
		if err != nil {
			return nil
		}
	}
	if len(msg) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, errors.New("Empty message"))
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, msg)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	return c.JSONPretty(http.StatusOK, RawSignatureResponse{hex.EncodeToString(signature)}, "  ")
}

func VerifyMessage(c echo.Context) error {
	request := new(VerifyRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	msg := []byte(request.Message)
	if request.MessageHex != "" {
		var err error
		msg, err = hex.DecodeString(request.MessageHex)
		if err != nil {
			return nil
		}
	}
	if len(msg) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, errors.New("Empty message"))
	}

	publicKeyCompressed, err := hex.DecodeString(request.PublicKey)
	if err != nil {
		return nil
	}
	publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, publicKeyCompressed)
	if err != nil {
		return nil
	}

	signature, _ := hex.DecodeString(request.Signature)
	r, _ := big.NewInt(0).SetString(hex.EncodeToString(signature[:32]), 16)
	s, _ := big.NewInt(0).SetString(hex.EncodeToString(signature[32:]), 16)
	verify := ecdsa.Verify(&publicKey, msg, r, s)

	return c.JSONPretty(http.StatusOK, VerifyResponse{Signature: request.Signature, Verified: verify}, "  ")
}

// RegisterRootKey
func RegisterRootKey(c echo.Context) error {
	cc := c.(*CustomContext)

	request := new(RootKeyRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	data, err := NewRootKeyCommandFromRootKeyRequest(request, TYPE_REGISTER_ROOT_KEY)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	// Do local validation:
	// Make sure the key is not taken and that if it is a replacing operation, correct private key is provided
	err = cc.Db.View(func(tx *bolt.Tx) error {
		bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
		existingPubKey := bRootKeys.Get([]byte(data.Username))
		if existingPubKey != nil {
			if request.PrivateKey == "" {
				return ErrPrivateKeyInvalid
			}

			var setSuccess bool
			privateKey := new(ecdsa.PrivateKey)
			privateKey.D, setSuccess = new(big.Int).SetString(request.PrivateKey, 16)
			if !setSuccess {
				return ErrPrivateKeyInvalid
			}

			privateKey.PublicKey.Curve = secp256k1Curve
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, data.BytesForSigning())
			if err != nil {
				return err
			}
			signature := r.Bytes()
			signature = append(signature, s.Bytes()...)
			copy(data.Signature[:], signature)

			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			verify := ecdsa.Verify(&publicKey, data.BytesForSigning(), r, s)
			if !verify {
				return ErrUsernameTaken
			}
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	response, err := carbonchain.Store(data.Bytes(), PACKET_ID, getFee(c), cc.BitcoindRpcOptions)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, TxIdResponse{response}, "  ")
}

// DeleteRootKey
func DeleteRootKey(c echo.Context) error {
	cc := c.(*CustomContext)

	request := new(RootKeyRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	data, err := NewRootKeyCommandFromRootKeyRequest(request, TYPE_DELETE_ROOT_KEY)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	if request.PrivateKey == "" {
		return ErrPrivateKeyInvalid
	}
	var setSuccess bool
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D, setSuccess = new(big.Int).SetString(request.PrivateKey, 16)
	if !setSuccess {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrPrivateKeyInvalid)
	}
	privateKey.PublicKey.Curve = secp256k1Curve
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data.BytesForSigning())
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	copy(data.Signature[:], signature)

	// Do local validation
	err = cc.Db.View(func(tx *bolt.Tx) error {
		bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
		existingPubKey := bRootKeys.Get([]byte(data.Username))
		if existingPubKey != nil {
			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			verify := ecdsa.Verify(&publicKey, data.BytesForSigning(), r, s)
			if !verify {
				return ErrNoAccess
			}
		} else {
			return ErrRootKeyDoesNotExist
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	response, err := carbonchain.Store(data.Bytes(), PACKET_ID, getFee(c), cc.BitcoindRpcOptions)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, TxIdResponse{response}, "  ")
}

// RegisterKey
func RegisterKey(c echo.Context) error {
	cc := c.(*CustomContext)

	request := new(KeyRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	data, err := NewKeyCommandFromKeyRequest(request, TYPE_REGISTER_KEY)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	// Do local validation
	err = cc.Db.View(func(tx *bolt.Tx) error {
		bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
		existingPubKey := bRootKeys.Get([]byte(data.Username))
		if existingPubKey != nil {
			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			r, _ := big.NewInt(0).SetString(hex.EncodeToString(data.Signature[:32]), 16)
			s, _ := big.NewInt(0).SetString(hex.EncodeToString(data.Signature[32:]), 16)
			verify := ecdsa.Verify(&publicKey, data.BytesForSigning(), r, s)
			if !verify {
				return ErrNoAccess
			}
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	response, err := carbonchain.Store(data.Bytes(), PACKET_ID, getFee(c), cc.BitcoindRpcOptions)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, TxIdResponse{response}, "  ")
}

// DeleteKey
func DeleteKey(c echo.Context) error {
	cc := c.(*CustomContext)

	request := new(KeyRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	data, err := NewKeyCommandFromKeyRequest(request, TYPE_DELETE_KEY)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	// Do local validation
	err = cc.Db.View(func(tx *bolt.Tx) error {
		bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
		existingPubKey := bRootKeys.Get([]byte(data.Username))
		if existingPubKey != nil {
			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			r, _ := big.NewInt(0).SetString(hex.EncodeToString(data.Signature[:32]), 16)
			s, _ := big.NewInt(0).SetString(hex.EncodeToString(data.Signature[32:]), 16)
			verify := ecdsa.Verify(&publicKey, data.BytesForSigning(), r, s)
			if !verify {
				return ErrNoAccess
			}
		} else {
			return ErrRootKeyDoesNotExist
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	response, err := carbonchain.Store(data.Bytes(), PACKET_ID, getFee(c), cc.BitcoindRpcOptions)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, TxIdResponse{response}, "  ")
}

// RegisterSignature
func RegisterSignature(c echo.Context) error {
	cc := c.(*CustomContext)

	request := new(SignatureRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	data := SignatureCommand{}
	data.Type = TYPE_REGISTER_SIGNATURE
	data.Username = request.Username
	if len(data.Username) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrUsernameEmpty)
	}
	data.ImageName = request.ImageName
	if len(data.ImageName) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrImageNameEmpty)
	}
	data.TagName = request.TagName
	if len(data.TagName) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrTagNameEmpty)
	}
	data.KeyId = request.KeyId
	data.Digests = request.Digests
	if len(data.Digests) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrDigestsEmpty)
	}
	for _, digest := range data.Digests {
		split := strings.Split(digest, ":")
		if len(split) != 2 {
			return ShowErrorJSON(c, http.StatusBadRequest, ErrDigestFormat)
		}
		_, err := hex.DecodeString(split[1])
		if err != nil {
			return ShowErrorJSON(c, http.StatusBadRequest, ErrDigestFormat)
		}
	}

	var setSuccess bool
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D, setSuccess = new(big.Int).SetString(request.PrivateKey, 16)
	if !setSuccess {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrPrivateKeyInvalid)
	}
	privateKey.PublicKey.Curve = secp256k1Curve
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data.BytesForSigning())
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	copy(data.Signature[:], signature)

	// Do local validation
	err = cc.Db.View(func(tx *bolt.Tx) error {
		bKeys := tx.Bucket([]byte(BUCKET_KEYS))
		bUsername := bKeys.Bucket([]byte(data.Username))
		if bUsername == nil {
			return ErrKeyNotFound
		}
		bImageName := bUsername.Bucket([]byte(data.ImageName))
		if bImageName == nil {
			return ErrKeyNotFound
		}
		existingPubKey := bImageName.Get([]byte{byte(data.KeyId)})
		if existingPubKey != nil {
			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			verify := ecdsa.Verify(&publicKey, data.BytesForSigning(), r, s)
			if !verify {
				return ErrNoAccess
			}
		} else {
			return ErrKeyDoesNotExist
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	response, err := carbonchain.Store(data.Bytes(), PACKET_ID, getFee(c), cc.BitcoindRpcOptions)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, TxIdResponse{response}, "  ")
}

// DeleteSignature
func DeleteSignature(c echo.Context) error {
	cc := c.(*CustomContext)

	request := new(SignatureRequest)
	if err := c.Bind(request); err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	data := SignatureCommand{}
	data.Type = TYPE_DELETE_SIGNATURE
	data.Username = request.Username
	if len(data.Username) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrUsernameEmpty)
	}
	data.ImageName = request.ImageName
	if len(data.ImageName) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrImageNameEmpty)
	}
	data.TagName = request.TagName
	if len(data.TagName) == 0 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrTagNameEmpty)
	}
	data.KeyId = request.KeyId

	var setSuccess bool
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D, setSuccess = new(big.Int).SetString(request.PrivateKey, 16)
	if !setSuccess {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrPrivateKeyInvalid)
	}
	privateKey.PublicKey.Curve = secp256k1Curve
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data.BytesForSigning())
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	copy(data.Signature[:], signature)

	// Do local validation
	err = cc.Db.View(func(tx *bolt.Tx) error {
		bKeys := tx.Bucket([]byte(BUCKET_KEYS))
		bUsername := bKeys.Bucket([]byte(data.Username))
		if bUsername == nil {
			return ErrKeyNotFound
		}
		bImageName := bUsername.Bucket([]byte(data.ImageName))
		if bImageName == nil {
			return ErrKeyNotFound
		}
		existingPubKey := bImageName.Get([]byte{byte(data.KeyId)})
		if existingPubKey != nil {
			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			verify := ecdsa.Verify(&publicKey, data.BytesForSigning(), r, s)
			if !verify {
				return ErrNoAccess
			}
		} else {
			return ErrKeyDoesNotExist
		}

		bSignatures := tx.Bucket([]byte(BUCKET_SIGNATURES))
		bUsername = bSignatures.Bucket([]byte(data.Username))
		if bUsername == nil {
			return ErrSignatureDoesNotExist
		}
		bImage := bUsername.Bucket([]byte(data.ImageName))
		if bImage == nil {
			return ErrSignatureDoesNotExist
		}
		bTag := bImage.Bucket([]byte(data.TagName))
		if bTag == nil {
			return ErrSignatureDoesNotExist
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	response, err := carbonchain.Store(data.Bytes(), PACKET_ID, getFee(c), cc.BitcoindRpcOptions)
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, TxIdResponse{response}, "  ")
}

// GetRootPublicKeyForUser
func GetRootPublicKeyForUser(c echo.Context) error {
	cc := c.(*CustomContext)

	username := c.Param("username")
	if username == "" {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrNameInvalid)
	}
	var publicKey string
	images := make([]string, 0)
	registeredRepo := make([]string, 0)
	err := cc.Db.View(func(tx *bolt.Tx) error {
		bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
		rootPublicKey := bRootKeys.Get([]byte(username))
		if rootPublicKey == nil {
			return ErrRootKeyNotFound
		}

		publicKey = hex.EncodeToString(rootPublicKey)

		bKeys := tx.Bucket([]byte(BUCKET_KEYS))
		bUsername := bKeys.Bucket([]byte(username))
		if bUsername == nil {
			return nil
		}

		bUsername.ForEach(func(k, v []byte) error {
			if v == nil {
				if bUsername.Bucket(k).Stats().KeyN > 0 && bUsername.Bucket(k).Stats().KeyN != bUsername.Bucket(k).Stats().BucketN-1 {
					registeredRepo = append(registeredRepo, string(k))
				}

				bSignatures := tx.Bucket([]byte(BUCKET_SIGNATURES))
				bUsername := bSignatures.Bucket([]byte(username))
				if bUsername == nil {
					return nil
				}
				bImage := bUsername.Bucket(k)
				if bImage == nil {
					return nil
				}

				bImage.ForEach(func(k2, v2 []byte) error {
					if v2 == nil {
						images = append(images, string(k)+":"+string(k2))
					}

					return nil
				})
			}

			return nil
		})

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, GetRootPublicKeyForUserResponse{PublicKeyCompressed: publicKey, Images: images, RegisteredRepo: registeredRepo}, "  ")
}

// GetPublicKeysForImage
func GetPublicKeysForImage(c echo.Context) error {
	cc := c.(*CustomContext)

	username := c.Param("username")
	if username == "" {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrNameInvalid)
	}
	imageName := c.Param("name")
	if imageName == "" {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrNameInvalid)
	}
	publicKeys := make(map[int]PublicKeyResponse, 0)
	err := cc.Db.View(func(tx *bolt.Tx) error {
		bKeys := tx.Bucket([]byte(BUCKET_KEYS))
		bUsername := bKeys.Bucket([]byte(username))
		if bUsername == nil {
			return ErrKeyNotFound
		}
		bImageName := bUsername.Bucket([]byte(imageName))
		if bImageName == nil {
			return ErrKeyNotFound
		}
		bMeta := bImageName.Bucket([]byte(BUCKET_META))
		if bMeta == nil {
			return ErrKeyNotFound
		}

		// Used for checking signature later
		command := KeyCommand{}
		command.Type = TYPE_REGISTER_KEY
		command.Username = username
		command.ImageName = imageName

		c := bImageName.Cursor()
		for keyId, publicKey := c.First(); keyId != nil; keyId, publicKey = c.Next() {
			// Not sure why we need to check for zero bytes
			if len(publicKey) == 0 {
				continue
			}

			copy(command.PublicKeyCompressed[:], publicKey)

			status := StatusUnableToVerify

			// Get signatureBytes
			key := append([]byte("signature_"), keyId[0])
			signatureBytes := bMeta.Get(key)
			if signatureBytes == nil {
				status = StatusSignatureNotValid
			} else {
				// Verify signatureBytes to check if expired
				func() {
					bRootKeys := tx.Bucket([]byte(BUCKET_ROOT_KEYS))
					rootPubKey := bRootKeys.Get([]byte(username))
					if rootPubKey == nil {
						status = StatusRootKeyDoesNotExist
						return
					}
					command.KeyId = int8(keyId[0])

					publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, rootPubKey)
					if err != nil {
						// TODO: Should I not panic?
						panic(err)
						return
					}

					r, _ := big.NewInt(0).SetString(hex.EncodeToString(signatureBytes[:32]), 16)
					s, _ := big.NewInt(0).SetString(hex.EncodeToString(signatureBytes[32:]), 16)
					verify := ecdsa.Verify(&publicKey, command.BytesForSigning(), r, s)
					if verify {
						status = StatusSignatureValid
						return
					} else {
						status = StatusSignatureNotValid
						return
					}
				}()
			}

			publicKeys[int(keyId[0])] = PublicKeyResponse{
				PublicKeyCompressed: hex.EncodeToString(publicKey),
				Signature:           hex.EncodeToString(signatureBytes),
				Status:              status,
			}
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	if len(publicKeys) == 0 {
		return ShowErrorJSON(c, http.StatusNotFound, ErrKeyNotFound)
	}

	return c.JSONPretty(http.StatusOK, GetPublicKeysForImageResponse{PublicKeys: publicKeys}, "  ")
}

// GetSignatureForTag
func GetSignatureForTag(c echo.Context) error {
	cc := c.(*CustomContext)

	username := c.Param("username")
	if username == "" {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrNameInvalid)
	}
	imageTagName := c.Param("name")
	imageTagNameSplit := strings.Split(imageTagName, ":")
	if len(imageTagNameSplit) != 2 {
		return ShowErrorJSON(c, http.StatusBadRequest, ErrNameInvalid)
	}
	imageName := imageTagNameSplit[0]
	tagName := imageTagNameSplit[1]

	hashes := make([]string, 0)
	var signatureBytes []byte
	keyId := int8(0)
	status := StatusUnableToVerify
	err := cc.Db.View(func(tx *bolt.Tx) error {
		bSignatures := tx.Bucket([]byte(BUCKET_SIGNATURES))
		bUsername := bSignatures.Bucket([]byte(username))
		if bUsername == nil {
			return ErrSignatureDoesNotExist
		}
		bImage := bUsername.Bucket([]byte(imageName))
		if bImage == nil {
			return ErrSignatureDoesNotExist
		}
		bTag := bImage.Bucket([]byte(tagName))
		if bTag == nil {
			return ErrSignatureDoesNotExist
		}

		c := bTag.Cursor()
		for i, hash := c.First(); i != nil; i, hash = c.Next() {
			// Not sure why we need to check for zero bytes
			if len(hash) == 0 {
				continue
			}

			hashes = append(hashes, string(hash))
		}

		bMeta := bTag.Bucket([]byte(BUCKET_META))
		if bMeta == nil {

		}
		keyIdBytes := bMeta.Get([]byte("keyId"))
		if keyIdBytes == nil {
			return ErrSignatureDoesNotExist
		}
		keyId = int8(keyIdBytes[0])
		signatureBytes = bMeta.Get([]byte("signature"))
		if signatureBytes == nil {
			return ErrSignatureDoesNotExist
		}

		// Verify signature to check if expired
		command := SignatureCommand{}
		command.Type = TYPE_REGISTER_SIGNATURE
		command.Username = username
		command.ImageName = imageName
		command.TagName = tagName
		command.KeyId = keyId
		command.Digests = hashes

		bKeys := tx.Bucket([]byte(BUCKET_KEYS))
		bUsername = bKeys.Bucket([]byte(username))
		if bUsername == nil {
			status = StatusRootKeyDoesNotExist
			return nil
		}
		bImageName := bUsername.Bucket([]byte(imageName))
		if bImageName == nil {
			status = StatusKeyDoesNotExist
			return nil
		}
		existingPubKey := bImageName.Get([]byte{byte(keyId)})
		if existingPubKey != nil {
			publicKey, err := UnserializePublicKeyCompressed(secp256k1Curve, existingPubKey)
			if err != nil {
				// TODO: Should I not panic?
				panic(err)
				return err
			}

			r, _ := big.NewInt(0).SetString(hex.EncodeToString(signatureBytes[:32]), 16)
			s, _ := big.NewInt(0).SetString(hex.EncodeToString(signatureBytes[32:]), 16)
			verify := ecdsa.Verify(&publicKey, command.BytesForSigning(), r, s)
			if verify {
				status = StatusSignatureValid
			} else {
				status = StatusSignatureNotValid
			}
		} else {
			status = StatusKeyDoesNotExist
			return nil
		}

		return nil
	})
	if err != nil {
		return ShowErrorJSON(c, http.StatusBadRequest, err)
	}

	return c.JSONPretty(http.StatusOK, GetSignatureForTagResponse{Name: username + "/" + imageTagName, Hashes: hashes, KeyId: keyId, Signature: hex.EncodeToString(signatureBytes), Status: status}, "  ")
}

func ShowErrorJSON(c echo.Context, code int, err error) error {
	c.JSONPretty(code, ErrorResponse{err.Error()}, "  ")
	return err
}

func getFee(c echo.Context) float64 {
	if c.Request().Header.Get("X-BTC-FEE") == "" {
		return DEFAULT_BTC_FEE
	}

	fee, err := strconv.ParseFloat(c.Request().Header.Get("X-BTC-FEE"), 64)
	if err != nil {
		return DEFAULT_BTC_FEE
	}

	return fee
}
