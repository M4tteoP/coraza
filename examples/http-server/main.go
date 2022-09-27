package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

var waf *coraza.WAF

func hello(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello world, not disrupted.\n")
}

func main() {
	if err := setupCoraza(); err != nil {
		panic(err)
	}
	http.Handle("/", corazaRequestHandler(http.HandlerFunc(hello)))

	fmt.Println("Server is running. Listening port: 8090")
	panic(http.ListenAndServe(":8090", nil))
}

func setupCoraza() error {
	waf = coraza.NewWAF()
	waf.SetDebugLogLevel(9)
	seclang := seclang.NewParser(waf)
	if err := seclang.FromString(`
		SecDebugLogLevel 6
		SecAuditEngine On
		SecRuleEngine On
		SecRequestBodyAccess On
		SecResponseBodyAccess On
		SecRule REQUEST_URI "@rx /admin" "id:101,phase:1,t:lowercase,deny"
		SecRule REQUEST_BODY "@rx maliciouspayload" "id:102,phase:2,t:lowercase,deny"
		SecRule RESPONSE_HEADERS::status "@rx 406" "id:103,phase:3,t:lowercase,deny"
		SecRule RESPONSE_BODY "@contains responsebodycode" "id:104,phase:4,t:lowercase,deny"
	`); err != nil {
		return err
	}
	return nil
}

func corazaRequestHandler(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction(context.Background())
		defer func() {
			// We run phase 5 rules and create audit logs (if enabled)
			tx.ProcessLogging()
			// we remove temporary files and free some memory
			if err := tx.Clean(); err != nil {
				fmt.Println(err)
			}
		}()
		w = &interceptor{
			origWriter: w,
			tx:         tx,
		}
		/*
			ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
			ProcessRequestHeaders and ProcessRequestBody.
			It fails if any of these functions returns an error and it stops on interruption.
		*/
		if it, err := txhttp.ProcessRequest(tx, r); err != nil {
			showCorazaError(w, 500, err.Error())
			return
		} else if it != nil {
			processInterruption(w, it)
			return
		}
		// We continue with the other middlewares by catching the response
		h.ServeHTTP(w, r)
		// we must intercept the response body :(
		if it, err := tx.ProcessResponseBody(); err != nil {
			showCorazaError(w, 500, err.Error())
			return
		} else if it != nil {
			processInterruption(w, it)
			return
		}
		// we release the buffer
		reader, err := tx.ResponseBodyBuffer.Reader()
		if err != nil {
			showCorazaError(w, 500, err.Error())
			return
		}
		if _, err := io.Copy(w, reader); err != nil {
			showCorazaError(w, 500, err.Error())
		}
	}

	return http.HandlerFunc(fn)
}

func processInterruption(w http.ResponseWriter, it *types.Interruption) {
	if it.Status == 0 {
		it.Status = 500
	}
	if it.Action == "deny" {
		showCorazaError(w, it.Status, "Transaction disrupted.")
	}
}

func showCorazaError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	if msg == "" {
		msg = "Unhandled error"
	}
	_, err := fmt.Fprintln(w, msg)
	if err != nil {
		fmt.Println(err)
	}
}
