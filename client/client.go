package client

import (
	"git.apache.org/thrift.git/lib/go/thrift"
	"io/ioutil"
	"log"
	"net"
	"quicksilver/stub"
	"strconv"
)

type Client struct {
	tClient *stub.UploadServerClient
}

func NewClient(host string, port int) *Client {
	transport, err := thrift.NewTSocket(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		log.Fatal(err)
	}

	pFactory := thrift.NewTBinaryProtocolFactoryDefault()
	c := stub.NewUploadServerClientFactory(transport, pFactory)

	if err := transport.Open(); err != nil {
		log.Fatal(err)
	}

	return &Client{tClient: c}
}

func (c *Client) Upload(path string) (etag *string, err error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return c.UploadByBytes(content)
}

func (c *Client) UploadByBytes(content []byte) (etag *string, err error) {
	img := &stub.Image{Path: "foobar", Size: int32(len(content)), Content: content}

	checksum, err := c.tClient.Upload(img)
	if err != nil {
		return nil, err
	}

	return &checksum, nil
}
