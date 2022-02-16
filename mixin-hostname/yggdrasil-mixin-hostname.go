package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/hjson/hjson-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"io/ioutil"
	"log"
	"net"
	"os"
	// "strings"
	"github.com/fps/yggdrasil-mdns/util"
)

type args struct {
	useconffile string
	// hostnamesuffix string
	// keysuffix      string
	logto    string
	hostname string
}

func getArgs() args {
	useconffile := flag.String("useconffile", "conf", "config file to read the private key from")
	// hostnamesuffix := flag.String("hostnamesuffix", "-ygg.local.", "the hostnamesuffix to answer for - make sure it ends with a dot, e.g.: \"-ygg.local.\"")
	// keysuffix := flag.String("keysuffix", "-yggk.local.", "the keysuffix to answer for - make sure it ends with a dot, e.g.: \"-yggk.local.\"")
	logto := flag.String("logto", "stdout", "where to log")

	default_hostname, err := os.Hostname()
	if err != nil {
		log.Println("Failed to retrieve hostname. Setting to \"\"")
		default_hostname = ""
	}

	hostname := flag.String("hostname", default_hostname, "the hostname to mix in")

	flag.Parse()
	return args{
		useconffile: *useconffile,
		// hostnamesuffix: *hostnamesuffix,
		// keysuffix:      *keysuffix,
		logto:    *logto,
		hostname: *hostname,
	}
}

func main() {
	args := getArgs()

	if args.logto == "stdout" {
		log.SetOutput(os.Stdout)
	} else {
		f, err := os.OpenFile(args.logto, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			fmt.Println("Failed to open log file:", err)
			return
		}
		log.SetOutput(f)
	}

	conf, err := ioutil.ReadFile(args.useconffile)
	if err != nil {
		log.Println("Failed to read config:", err)
		return
	}

	var cfg map[string]interface{}
	err = hjson.Unmarshal(conf, &cfg)
	if err != nil {
		log.Println("Failed to decode config:", err)
		return
	}

	sigPriv, err := hex.DecodeString(cfg["PrivateKey"].(string))
	if err != nil {
		log.Println("Failed to decode private key", err)
		return
	}

	privateKey := ed25519.PrivateKey(sigPriv)

	hostname, err := os.Hostname()
	if err != nil {
		log.Println("Failed to retrieve hostname", err)
		return
	}

	mixedInPrivateKey := util.MixinHostname(privateKey, hostname)
	mixedInPublicKey := mixedInPrivateKey.Public().(ed25519.PublicKey)

	log.Println("Mixed in keys:")
	log.Println("Private:", hex.EncodeToString(mixedInPrivateKey))
	log.Println("Public:", hex.EncodeToString(mixedInPublicKey))

	address := address.AddrForKey(mixedInPublicKey)
	bytes := [16]byte(*address)

	log.Println("Address:", net.IP(bytes[:]).String())
	log.Println("Address (base32):", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mixedInPublicKey))
}
