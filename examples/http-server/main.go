package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/loggers"
	ctypes "github.com/corazawaf/coraza/v3/types"
)

func hello(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello world, not disrupted.\n")
}

func main() {
	waf, err := setupCoraza()
	if err != nil {
		panic(err)
	}
	http.Handle("/hello", corazaRequestHandler(waf, http.HandlerFunc(hello)))

	fmt.Println("Server is running. Listening port: 8090")
	panic(http.ListenAndServe(":8090", nil))
}

func setupCoraza() (coraza.WAF, error) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithErrorLogger(logError).
		WithDebugLogger(&debugLogger{}).
		WithDirectives(`
		# This is a comment
		SecDebugLogLevel 5
		SecRequestBodyAccess On
		SecResponseBodyAccess On
		SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
		SecRule REQUEST_BODY "somecontent" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
		SecRule RESPONSE_BODY "somecontent" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
	`))
	if err != nil {
		return nil, err
	}
	return waf, err
}

func corazaRequestHandler(waf coraza.WAF, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction(context.Background())
		defer func() {
			// We run phase 5 rules and create audit logs (if enabled)
			tx.ProcessLogging()
			// we remove temporary files and free some memory
			if err := tx.Close(); err != nil {
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
		body, _ := io.ReadAll(r.Body)
		fmt.Println("Dumping Body:", string(body))
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
		reader, err := tx.ResponseBodyReader()
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

func processInterruption(w http.ResponseWriter, it *ctypes.Interruption) {
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

func logError(error ctypes.MatchedRule) {
	msg := error.ErrorLog(0)
	switch error.Rule.Severity {
	case ctypes.RuleSeverityEmergency:
	case ctypes.RuleSeverityAlert:
	case ctypes.RuleSeverityCritical:
		fmt.Println(msg)
	case ctypes.RuleSeverityError:
		fmt.Println(msg)
	case ctypes.RuleSeverityWarning:
		fmt.Println(msg)
	case ctypes.RuleSeverityNotice:
		fmt.Println(msg)
	case ctypes.RuleSeverityInfo:
		fmt.Println(msg)
	case ctypes.RuleSeverityDebug:
		fmt.Println(msg)
	}
}

type debugLogger struct {
	level loggers.LogLevel
}

func (l *debugLogger) Info(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelInfo {
		fmt.Printf(message, args...)
	}
}

func (l *debugLogger) Warn(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelWarn {
		fmt.Printf(message, args...)
	}
}

func (l *debugLogger) Error(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelError {
		fmt.Printf(message, args...)
	}
}

func (l *debugLogger) Debug(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelDebug {
		fmt.Printf(message, args...)
	}
}

func (l *debugLogger) Trace(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelTrace {
		fmt.Printf(message, args...)
	}
}

func (l *debugLogger) SetLevel(level loggers.LogLevel) {
	l.level = level
}

func (l *debugLogger) SetOutput(w io.Writer) {
	fmt.Println("ignoring SecDebugLog directive, debug logs are always routed to proxy logs")
}
