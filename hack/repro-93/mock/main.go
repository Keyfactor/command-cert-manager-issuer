// Mock Keyfactor Command that always answers 503.
//   vary  - body contains a unique CorrelationId on every request
//   fixed - body is identical on every request
// Each request is logged as: <epoch_ms> <n> <method> <path>
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) != 4 || (os.Args[1] != "vary" && os.Args[1] != "fixed") {
		log.Fatal("usage: mock <vary|fixed> <cert.pem> <key.pem>")
	}
	mode := os.Args[1]
	var n atomic.Int64
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		i := n.Add(1)
		now := time.Now()
		fmt.Printf("%d %d %s %s\n", now.UnixMilli(), i, r.Method, r.URL.Path)
		w.WriteHeader(http.StatusServiceUnavailable)
		if mode == "vary" {
			fmt.Fprintf(w, `{"Message":"upstream unavailable","CorrelationId":"req-%d-%d"}`, i, now.UnixNano())
		} else {
			fmt.Fprint(w, "no healthy upstream")
		}
	})
	log.Fatal(http.ListenAndServeTLS(":8443", os.Args[2], os.Args[3], nil))
}
