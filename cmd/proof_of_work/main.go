package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/regnull/raven/pbraven"
)

func main() {
	r := &pbraven.NameRegistrationRecord{
		Name:        "regnull",
		Destination: "127.0.0.1",
		Recipient:   "foo"}

	r1, err := ComputeProofOfWork(context.Background(), r, 4, 10*time.Minute)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	fmt.Printf("found POW: %d\n", r1.ProofOfWork)
}

// ComputeProofOfWork computes proof of work for name registration record.
func ComputeProofOfWork(ctx context.Context, r *pbraven.NameRegistrationRecord, n int,
	maxDuration time.Duration) (*pbraven.NameRegistrationRecord, error) {
	ctx1, cancel := context.WithCancel(ctx)
	var (
		wg   sync.WaitGroup
		res  *pbraven.NameRegistrationRecord
		lock sync.Mutex
		err  error
	)

	// Start time monitoring goroutine.
	start := time.Now()
	go func() {
		wg.Add(1)
		defer wg.Done()
		for {
			// Check if the context is done.
			select {
			case <-ctx1.Done():
				return
			default:
			}
			if time.Now().Sub(start) > maxDuration {
				lock.Lock()
				defer lock.Unlock()
				err = fmt.Errorf("failed to compute POW: time exceeded")
				cancel()
				return
			}
		}
	}()

	// Start worker goroutines.
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		func() {
			rnd := rand.New(rand.NewSource(int64(i*1234 + time.Now().Nanosecond())))
			defer wg.Done()
			r1 := proto.Clone(r).(*pbraven.NameRegistrationRecord)
			for {
				// Check if the context is done.
				select {
				case <-ctx1.Done():
					return
				default:
				}
				r1.ProofOfWork = rnd.Int63()
				data, err1 := proto.Marshal(r1)
				if err != nil {
					lock.Lock()
					defer lock.Unlock()
					if err == nil {
						// Only the first error is returned.
						err = err1
					}
					return
				}
				h := sha256.New()
				h.Write(data)
				if verifyPOW(h.Sum(nil), n) {
					lock.Lock()
					defer lock.Unlock()
					if err != nil || res != nil {
						// Only the first result (or the first error) is returned.
						return
					}
					res = r1
					cancel() // Tell all other goroutines to go away.
					return
				}
			}
		}()
	}
	wg.Wait()
	return res, err
}

func verifyPOW(hash []byte, n int) bool {
	//fmt.Printf("%x\n", hash)
	if len(hash) < n {
		return false
	}
	for i := 1; i <= n; i++ {
		if hash[len(hash)-i] != 0 {
			return false
		}
	}
	fmt.Printf("%x\n", hash)
	return true
}
