package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/client"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"log"
	"strconv"
	"strings"
)

func CmdSignAndSubmit(host string, port string, args []string) error {
	privateKey := args[1]
	_, err := hex.DecodeString(privateKey)
	if err != nil {
		return err
	}
	keyId, err := strconv.Atoi(args[2])
	if err != nil {
		return err
	}
	imageName := args[3]
	imageNameSplit := strings.Split(imageName, "/")
	if len(imageNameSplit) != 2 {
		return errors.New("Invalid image name provided")
	}
	username := imageNameSplit[0]
	imageNameSplit = strings.Split(imageNameSplit[1], ":")
	if len(imageNameSplit) != 2 {
		return errors.New("Invalid image name provided")
	}
	imageName = imageNameSplit[0]
	tagName := imageNameSplit[1]

	hashes, err := getHashesForImage(args[3])
	log.Printf("Hashes for image %s:\n", args[3])
	hashesJson, _ := json.MarshalIndent(hashes, "", "\t")
	log.Printf("\n%s\n", hashesJson)

	if len(hashes) == 0 {
		return errors.New("Image not found in Docker")
	}

	registerSignatureBody := SignatureRequest{
		PrivateKey: privateKey,
		KeyId:      int8(keyId),
		Username:   username,
		ImageName:  imageName,
		TagName:    tagName,
		Digests:    hashes,
	}
	requestJson, _ := json.MarshalIndent(registerSignatureBody, "", "\t")
	log.Printf("Sending POST:\n%s\n", requestJson)

	var txIdResponse TxIdResponse

	res, _, errs := gorequest.New().Post("http://"+host+":"+port+"/registerSignature").
		Set("X-BTC-FEE", "0.00001").
		Send(string(requestJson)).
		EndStruct(&txIdResponse)

	if len(errs) != 0 {
		return errs[0]
	}
	if res.StatusCode != 200 {
		return errors.New("Did not receive expected response from trust daemon")
	}

	resJson, _ := json.MarshalIndent(txIdResponse, "", "\t")
	log.Printf("Response:\n%s\n", resJson)

	return nil
}

func CmdVerify(host string, port string, args []string) error {
	hashes, err := getHashesForImage(args[1])
	if err != nil {
		return err
	}
	log.Printf("Hashes for image %s:\n", args[1])
	hashesJson, _ := json.MarshalIndent(hashes, "", "\t")
	log.Printf("\n%s\n", hashesJson)

	if len(hashes) == 0 {
		return errors.New("Image not found in Docker")
	}

	var getSignatureForTagResponse GetSignatureForTagResponse
	res, _, errs := gorequest.New().Get("http://" + host + ":" + port + "/get/" + args[1]).EndStruct(&getSignatureForTagResponse)
	if len(errs) != 0 {
		return errs[0]
	}
	if res.StatusCode != 200 {
		return errors.New("Did not receive expected response from trust daemon")
	}

	log.Println("Response from trust:")
	resJson, _ := json.MarshalIndent(getSignatureForTagResponse, "", "\t")
	log.Printf("\n%s\n", resJson)

	if len(getSignatureForTagResponse.Hashes) != len(hashes) {
		return errors.New("Hashes count does not match")
	}

	for i := 0; i < len(hashes); i++ {
		if hashes[i] != getSignatureForTagResponse.Hashes[i] {
			return errors.New(fmt.Sprintf("Hashes does not match at index %d", i))
		}
	}

	log.Printf("Hashes matches! Signature Status: %s\n", getSignatureForTagResponse.Status)

	return nil
}

func getHashesForImage(imageName string) ([]string, error) {
	dockerClient, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	inspect, _, err := dockerClient.ImageInspectWithRaw(context.Background(), strings.Replace(imageName, "docker/", "", 1))
	if err != nil {
		return []string{}, err
	}

	hashes := make([]string, len(inspect.RootFS.Layers)+1)
	hashes[0] = strings.Split(inspect.RepoDigests[0], "@")[1]
	for i := 1; i < len(hashes); i++ {
		hashes[i] = inspect.RootFS.Layers[i-1]
	}

	return hashes, nil
}
