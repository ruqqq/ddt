package main

import (
	"flag"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/ruqqq/blockchainparser/rpc"
	"github.com/ruqqq/carbonchain"
	"log"
	"os"
	"runtime"
	"strings"
)

const (
	PACKET_ID = 0xdf
)

func main() {
	var help bool
	var gomaxprocs int
	var testnet bool
	var datadir string
	var logLevel int
	var host string
	var port string
	var bitcoindIp string
	var bitcoindPort string
	var bitcoindRpcUser string
	var bitcoindRpcPass string
	flag.BoolVar(&testnet, "testnet", false, "Use testnet")
	flag.StringVar(&datadir, "datadir", "", "Bitcoin data path")
	flag.IntVar(&gomaxprocs, "gomaxprocs", -1, "Number of threads to use")
	flag.IntVar(&logLevel, "loglevel", carbonchain.LOG_LEVEL_ERROR, "Set log level: 0-4; Default: 4")
	flag.StringVar(&host, "host", "localhost", "Host for SignAndSubmit/Verify commands to connect to")
	flag.StringVar(&port, "port", "1323", "Port to run daemon on. For SignAndSubmit/Verify commands, port to connect to")
	flag.StringVar(&bitcoindIp, "rpcip", bitcoindIp, "Bitcoind RPC IP\n\t\t* REQUIRED ONLY FOR STORE COMMAND")
	flag.StringVar(&bitcoindPort, "rpcport", bitcoindPort, "Bitcoind RPC Port (Default for testnet set to append 1 to this variable)\n\t\t* REQUIRED ONLY FOR store COMMAND")
	flag.StringVar(&bitcoindRpcUser, "rpcuser", bitcoindRpcUser, "User for bitcoind RPC\n\t\t* REQUIRED ONLY FOR store COMMAND")
	flag.StringVar(&bitcoindRpcPass, "rpcpassword", bitcoindRpcPass, "Password for bitcoind RPC\n\t\t* REQUIRED ONLY FOR store COMMAND")
	flag.BoolVar(&help, "help", help, "Show help")
	flag.Parse()

	log.Printf("testnet: %v\n", testnet)
	log.Printf("datadir: %s\n", datadir)
	wd, _ := os.Getwd()
	log.Printf("app datadir: %s\n", wd)
	args := flag.Args()

	bitcoindRpcOptions := &rpc.RpcOptions{
		Host:    bitcoindIp,
		Port:    bitcoindPort,
		User:    bitcoindRpcUser,
		Pass:    bitcoindRpcPass,
		Testnet: testnet,
	}

	runtime.GOMAXPROCS(gomaxprocs)
	log.Printf("GOMAXPROCS: %d\n", runtime.GOMAXPROCS(-1))

	showHelp := func() {
		fmt.Fprint(os.Stderr, "Distributed Docker Trust\n(c)2017 Faruq Rasid\n\n"+
			"  SignAndSubmit <private key> <key id> <image:tag>\n"+
			"  Verify <image:tag>\n"+
			"Options:\n")
		flag.PrintDefaults()
	}

	if help {
		showHelp()
		return
	}

	if len(args) > 3 && strings.ToLower(args[0]) == "signandsubmit" {
		err := CmdSignAndSubmit(host, port, args)
		if err != nil {
			log.Fatal(err)
		}
		return
	} else if len(args) > 1 && strings.ToLower(args[0]) == "verify" {
		err := CmdVerify(host, port, args)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if len(args) != 0 {
		showHelp()
		return
	}

	db := initDb(testnet)
	defer db.Close()

	datapackWorker := &DatapackWorker{Db: db}

	cc, err := carbonchain.NewCarbonChainWithDb(&carbonchain.CarbonChainOptions{LogLevel: logLevel, Testnet: testnet, DataDir: datadir, PacketId: PACKET_ID, ProcessFunc: datapackWorker.OnReceiveDatapacks})
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Close()

	err = cc.Init()
	if err != nil {
		panic(err)
	}

	done := make(chan bool)
	go func() {
		err = cc.Watch(done)
		if err != nil {
			panic(err)
		}
	}()

	startHttpServer(port, db, bitcoindRpcOptions)
}

func initDb(testnet bool) *bolt.DB {
	prefix := ""
	if testnet {
		prefix = "testnet_"
	}

	db, err := bolt.Open(prefix+"ddt.db", 0600, nil)
	if err != nil {
		panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BUCKET_ROOT_KEYS))
		if err != nil {
			return fmt.Errorf("error create/open bucket: %s", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(BUCKET_KEYS))
		if err != nil {
			return fmt.Errorf("error create/open bucket: %s", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(BUCKET_SIGNATURES))
		if err != nil {
			return fmt.Errorf("error create/open bucket: %s", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(BUCKET_COMMANDS))
		if err != nil {
			return fmt.Errorf("error create/open bucket: %s", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(BUCKET_DATAPACKS))
		if err != nil {
			return fmt.Errorf("error create/open bucket: %s", err)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	return db
}

func startHttpServer(port string, db *bolt.DB, bitcoindRpcOptions *rpc.RpcOptions) {
	e := echo.New()
	e.Use(func(h echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cc := &CustomContext{Context: c, BitcoindRpcOptions: bitcoindRpcOptions, Db: db}
			return h(cc)
		}
	})
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))
	e.GET("/createKeyPair", CreateKeyPair)
	e.POST("/signMessage", SignMessage)
	e.POST("/verifyMessage", VerifyMessage)

	e.GET("/:username", GetRootPublicKeyForUser)
	e.POST("/:username", RegisterRootKey)
	e.DELETE("/:username", DeleteRootKey)

	e.GET("/:username/:name", func(c echo.Context) error {
		if len(strings.Split(c.Param("name"), ":")) == 2 {
			return GetSignatureForTag(c)
		} else {
			return GetPublicKeysForImage(c)
		}
	})
	e.POST("/:username/:name", func(c echo.Context) error {
		if len(strings.Split(c.Param("name"), ":")) == 2 {
			return RegisterSignature(c)
		} else {
			return RegisterKey(c)
		}
	})
	e.DELETE("/:username/:name", func(c echo.Context) error {
		if len(strings.Split(c.Param("name"), ":")) == 2 {
			return DeleteSignature(c)
		} else {
			return DeleteKey(c)
		}
	})

	e.Logger.Fatal(e.Start(":" + port))
}
