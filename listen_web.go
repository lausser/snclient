package snclient

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

const (
	// DefaultPassword sets default password, login with default password is not
	// possible. It needs to be changed in the ini file.
	DefaultPassword = "CHANGEME"
)

type CheckWebResponse struct {
	Payload []CheckWebPayload `json:"payload"`
}

type CheckWebLine struct {
	Message string         `json:"message"`
	Perf    []CheckWebPerf `json:"perf,omitempty"`
}

type CheckWebPerf struct {
	Alias  string             `json:"alias"`
	IntVal CheckWebPerfIntVal `json:"int_value,omitempty"`
}

type CheckWebPerfIntVal struct {
	Value    int64  `json:"value"`
	Unit     string `json:"unit"`
	Warning  string `json:"warning"`
	Critical string `json:"critical"`
}

type CheckWebPayload struct {
	Command string         `json:"command"`
	Result  string         `json:"result"`
	Lines   []CheckWebLine `json:"lines"`
}

func init() {
	AvailableListeners = append(AvailableListeners, ListenHandler{"WEBServer", "/settings/WEB/server", NewHandlerWeb()})
}

type HandlerWeb struct {
	noCopy        noCopy
	handlerLegacy http.Handler
	handlerV1     http.Handler
	snc           *Agent
	password      string
}

func NewHandlerWeb() *HandlerWeb {
	l := &HandlerWeb{}
	l.handlerLegacy = &HandlerWebLegacy{Handler: l}
	l.handlerV1 = &HandlerWebV1{Handler: l}

	return l
}

func (l *HandlerWeb) Type() string {
	return "web"
}

func (l *HandlerWeb) Defaults() ConfigData {
	defaults := ConfigData{
		"port":     "8443",
		"use ssl":  "1",
		"password": DefaultPassword,
	}
	defaults.Merge(DefaultListenHTTPConfig)

	return defaults
}

func (l *HandlerWeb) Init(snc *Agent, conf *ConfigSection) error {
	l.snc = snc

	if password, ok := conf.GetString("password"); ok {
		l.password = password
	}

	return nil
}

func (l *HandlerWeb) GetMappings(*Agent) []URLMapping {
	return []URLMapping{
		{URL: "/query/{command}", Handler: l.handlerLegacy},
		{URL: "/api/v1/queries/{command}/commands/execute", Handler: l.handlerV1},
	}
}

func (l *HandlerWeb) Check(res http.ResponseWriter, command string, args []string) {
	result := l.snc.RunCheck(command, args)
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	LogError(json.NewEncoder(res).Encode(CheckWebResponse{
		Payload: []CheckWebPayload{
			{
				Command: command,
				Result:  result.StateString(),
				Lines: []CheckWebLine{
					{
						Message: result.Output,
						Perf:    l.metrics2Perf(result.Metrics),
					},
				},
			},
		},
	}))
}

func (l *HandlerWeb) verifyPassword(password string) bool {
	// password checks are disabled
	if l.password == "" {
		return true
	}

	// no login with default password
	if l.password == DefaultPassword {
		log.Errorf("password matches default password -> 403")

		return false
	}

	if l.password == password {
		return true
	}

	log.Errorf("password mismatch -> 403")

	return false
}

func queryParam2CommandArgs(req *http.Request) []string {
	args := make([]string, 0)

	query := req.URL.RawQuery
	if query == "" {
		return args
	}

	for _, v := range strings.Split(query, "&") {
		u, _ := url.QueryUnescape(v)
		args = append(args, u)
	}

	return args
}

func (l *HandlerWeb) metrics2Perf(metrics []*CheckMetric) []CheckWebPerf {
	if len(metrics) == 0 {
		return nil
	}
	result := make([]CheckWebPerf, 0)

	for _, m := range metrics {
		perf := CheckWebPerf{
			Alias: m.Name,
			IntVal: CheckWebPerfIntVal{
				Value: int64(m.Value),
				Unit:  m.Unit,
			},
		}
		result = append(result, perf)
	}

	return result
}

type HandlerWebLegacy struct {
	noCopy  noCopy
	Handler *HandlerWeb
}

func (l *HandlerWebLegacy) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// check clear text password
	if !l.Handler.verifyPassword(req.Header.Get("Password")) {
		http.Error(res, http.StatusText(http.StatusForbidden), http.StatusForbidden)

		return
	}

	l.Handler.Check(res, chi.URLParam(req, "command"), queryParam2CommandArgs(req))
}

type HandlerWebV1 struct {
	noCopy  noCopy
	Handler *HandlerWeb
}

func (l *HandlerWebV1) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// check basic auth password
	_, password, _ := req.BasicAuth()
	if !l.Handler.verifyPassword(password) {
		http.Error(res, http.StatusText(http.StatusForbidden), http.StatusForbidden)

		return
	}

	l.Handler.Check(res, chi.URLParam(req, "command"), queryParam2CommandArgs(req))
}
