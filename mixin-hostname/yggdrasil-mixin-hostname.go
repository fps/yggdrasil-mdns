package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/hjson/hjson-go"
	"github.com/libp2p/go-reuseport"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv6"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
    "github.com/fps/yggdrasil-mdns/util"
)

type args struct {
	useconffile    string
	hostnamesuffix string
	keysuffix      string
}

func getArgs() args {
	useconffile := flag.String("useconffile", "conf", "config file to read the private key from")
	port := flag.Int("port", 5353, "port to listen on (UDP)")
	hostnamesuffix := flag.String("hostnamesuffix", "-ygg.local.", "the hostnamesuffix to answer for - make sure it ends with a dot, e.g.: \"-ygg.local.\"")
	keysuffix := flag.String("keysuffix", "-yggk.local.", "the keysuffix to answer for - make sure it ends with a dot, e.g.: \"-yggk.local.\"")

	flag.Parse()
	return args{
		useconffile:    *useconffile,
		hostnamesuffix: *hostnamesuffix,
		keysuffix:      *keysuffix,
	}
}

var privateKey []byte
var hostnamesuffix string
var keysuffix string

func processHostnameQuery(q dnsmessage.Question, msg dnsmessage.Message) ([]byte, error) {
	trimmed := strings.TrimSuffix(q.Name.String(), hostnamesuffix)
	log.Println("Network be asking for:", q.Name.String(), "Trimmed:", trimmed, "Suffix: ", hostnamesuffix)
	mixedPriv := util.MixinHostname(ed25519.PrivateKey(privateKey), trimmed)
	resolved := address.AddrForKey(mixedPriv.Public().(ed25519.PublicKey))

	rsp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: msg.Header.ID, Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.AAAAResource{AAAA: *resolved},
			},
		},
	}

	rspbuf, err := rsp.Pack()
	if err != nil {
		log.Println("Error packing: ", err)
		return nil, err
	}

	return rspbuf, nil
}

func processKeyQuery(q dnsmessage.Question, msg dnsmessage.Message) ([]byte, error) {
	trimmed := strings.TrimSuffix(q.Name.String(), keysuffix)
	log.Println("Network be asking for:", q.Name.String(), "Trimmed:", trimmed, "Suffix: ", keysuffix)

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(trimmed)
	if err != nil {
		log.Println("Error decoding key:", err)
		return nil, err
	}

	resolved := address.AddrForKey(key)

	rsp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: msg.Header.ID, Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.AAAAResource{AAAA: *resolved},
			},
		},
	}

	rspbuf, err := rsp.Pack()
	if err != nil {
		log.Println("Error packing: ", err)
		return nil, err
	}

	return rspbuf, nil
}

func processQuery(msg dnsmessage.Message, remote *net.UDPAddr, srvaddr string) ([]byte, error) {
	for _, q := range msg.Questions {
		if q.Type != dnsmessage.TypeAAAA {
			continue
		}

		var rsp []byte = nil
		var err error = nil

		if strings.HasSuffix(q.Name.String(), hostnamesuffix) {
			rsp, err = processHostnameQuery(q, msg)
			if err != nil {
				log.Println("Error processing hostname query:", err)
				return nil, err
			}
			return rsp, nil
		}

		if strings.HasSuffix(q.Name.String(), keysuffix) {
			rsp, err = processKeyQuery(q, msg)
			if err != nil {
				log.Println("Error processing key query:", err)
				return nil, err
			}
			return rsp, nil
		}
	}
	return nil, fmt.Errorf("No question in query")
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

	sigPriv, _ := hex.DecodeString(cfg["PrivateKey"].(string))
	privateKey = sigPriv
	hostnamesuffix = args.hostnamesuffix
	keysuffix = args.keysuffix

}
