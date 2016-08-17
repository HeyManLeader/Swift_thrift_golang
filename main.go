package main

import (
	"git.apache.org/thrift.git/lib/go/thrift"
	"log"
	"quicksilver/server"
	"quicksilver/stub"
)

func main() {
	pFactory := thrift.NewTBinaryProtocolFactoryDefault()
	tFactory := thrift.NewTBufferedTransportFactory(8192)
	addr := "0.0.0.0:9090"

	transport, err := thrift.NewTServerSocket(addr)
	if err != nil {
		log.Fatal(err)
	}

	handler := server.NewUploadServerHandler()
	processor := stub.NewUploadServerProcessor(handler)

	server := thrift.NewTSimpleServer4(processor, transport, tFactory, pFactory)

	server.Serve()
}
