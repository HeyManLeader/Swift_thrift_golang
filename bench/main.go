package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"quicksilver/client"
	"strconv"
	"time"

	"github.com/jolestar/go-commons-pool"
)

type Src struct {
	Data     []byte
	Checksum string
}

func createFunc(host string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return client.NewClient(host, 9090), nil
	}
}

func main() {
	concurrency, _ := strconv.Atoi(os.Args[1])
	tasks, _ := strconv.Atoi(os.Args[2])
	cap, _ := strconv.Atoi(os.Args[3])

	hosts := []string{"10.221.72.169", "10.221.72.180", "10.221.72.182", "10.221.72.183", "10.221.72.168", "10.221.72.188"}
	pools := make(map[string]*pool.ObjectPool)

	for _, host := range hosts {
		p := pool.NewObjectPoolWithDefaultConfig(pool.NewPooledObjectFactorySimple(createFunc(host)))
		p.Config.MaxTotal = cap
		p.Config.MaxIdle = cap
		pools[host] = p
	}

	ch := make(chan time.Duration, concurrency)
	success := make(chan int, concurrency)

	var srcs [1000]Src

	for i := range srcs {
		f := strconv.Itoa(rand.Intn(10000))
		p := fmt.Sprintf("/data/losfs/%s", f)
		data, err := ioutil.ReadFile(p)
		if err != nil {
			log.Fatal("fail to open file %s\n", err)
		}

		checksum := md5.Sum(data)
		srcs[i] = Src{Data: data, Checksum: hex.EncodeToString(checksum[:])}
	}

	begin := time.Now()

	for j := 0; j < concurrency; j++ {
		go func(r int) {
			var duration time.Duration
			succ := 0
			for i := 0; i < tasks; i++ {
				start := time.Now()
				h := hosts[rand.Intn(6)]
				pool := pools[h]
				obj, _ := pool.BorrowObject()
				c := obj.(*client.Client)
				src := srcs[rand.Intn(1000)]
				if etag, err := c.UploadByBytes(src.Data); err == nil {
					if *etag == src.Checksum {
						pool.ReturnObject(obj)
						duration += time.Since(start)
						succ++
					} else {
						log.Printf("checksums not match: %s : %s", src.Checksum, etag)
					}
				} else {
					log.Println(err)
				}

			}

			ch <- duration
			success <- succ
		}(j)
	}

	var elapsed time.Duration
	count := 0
	for i := 0; i < concurrency; i++ {
		elapsed += <-ch
		count += <-success
	}

	all := concurrency * tasks
	log.Printf("real time: %s", time.Since(begin))
	log.Printf("it took %s", elapsed)
	log.Printf("success requests: %d", count)
	log.Printf("fail rate: %f", float64(all-count)/float64(all))
	log.Printf("time cost per request: %fms", float64(elapsed/time.Millisecond)/float64(count))
}
