package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		panic(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		panic(err)
	}
	fmt.Println(l.Addr())
	for {
		c, e := l.Accept()
		if e != nil {
			panic(e)
		}
		go func(c net.Conn) {
			defer c.Close()
			r, e := http.ReadRequest(bufio.NewReader(c))
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
				return
			}
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}(c)
	}
}
