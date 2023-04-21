package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"reflect"
	"strconv"
)

type MetricsDef struct {
	QueriesSent     *prometheus.CounterVec
	QueriesReceived *prometheus.CounterVec
	QueriesInflight prometheus.Gauge
	QueriesRTT      prometheus.Histogram

	QueryResponses *prometheus.CounterVec

	Hits   prometheus.Counter
	Misses prometheus.Counter
	
	//RateLimitWaitTime *prometheus.HistogramVec
	//
	//TCPDialErrors prometheus.Counter
	//
	//TCPClientSendOnDeadConn          prometheus.Counter
	//TCPClientRecoveredSendOnDeadConn prometheus.Counter
	//
	//TCPConnsOpen   *prometheus.GaugeVec
	//TCPConnsOpened *prometheus.CounterVec
	//
	//TCPPoolExhausted          prometheus.Counter
	//TCPPoolEphemeralExhausted prometheus.Counter
}

var M = MetricsDef{
	QueriesSent: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "client_queries_sent",
		Help: "The number queries sent to the wire",
	}, []string{"transport", "ip"}),
	QueriesReceived: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "client_queries_received",
		Help: "The number responses received",
	}, []string{"transport", "ip"}),
	QueriesInflight: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "client_queries_inflight",
		Help: "The number queries that is currently inflight",
	}),
	QueriesRTT: prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "client_queries_rtt",
		Help:    "Round trip time for a request.",
		Buckets: prometheus.DefBuckets,
	}),
	QueryResponses: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "resolver_query_responses",
		Help: "The total number of query responses received in the retrying client.",
	}, []string{"rcode", "truncated", "hasErr", "isFinal"}),

	Hits: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_hits",
		Help: "The total number of cache hits",
	}),
	Misses: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_misses",
		Help: "The total number of cache misses",
	}),

	//RateLimitWaitTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
	//	Name:    "client_ratelimiting_duration_seconds",
	//	Help:    "Wait time for a request due to the rate limiting in seconds.",
	//	Buckets: prometheus.DefBuckets,
	//}, []string{"type"}),
	//TCPDialErrors: prometheus.NewCounter(prometheus.CounterOpts{
	//	Name: "client_tcp_dial_errors",
	//	Help: "The total number of TCP connections that encountered an error on dialing",
	//}),
	//TCPConnsOpen: prometheus.NewGaugeVec(prometheus.GaugeOpts{
	//	Name: "client_tcp_conn_open",
	//	Help: "The number of times a pooled connection has been opened successfully.",
	//}, []string{"type"}),
	//TCPConnsOpened: prometheus.NewCounterVec(prometheus.CounterOpts{
	//	Name: "client_tcp_conn_opened",
	//	Help: "The number of times a pooled connection has been opened successfully.",
	//}, []string{"type"}),
	//TCPPoolEphemeralExhausted: prometheus.NewCounter(prometheus.CounterOpts{
	//	Name: "client_tcp_pool_ephemeral_conns",
	//	Help: "The number of times an ephemeral connection was requested but the maximum number was reached.",
	//}),
	//TCPPoolExhausted: prometheus.NewCounter(prometheus.CounterOpts{
	//	Name: "client_tcp_pool_exhausted",
	//	Help: "The number of times a connection has been requested but the pool was exhausted.",
	//}),
	//TCPClientSendOnDeadConn: prometheus.NewCounter(prometheus.CounterOpts{
	//	Name: "client_tcp_send_on_dead_conn",
	//	Help: "The total number of times it was tried to send a query on a TCP conn that was already closed.",
	//}),
	//TCPClientRecoveredSendOnDeadConn: prometheus.NewCounter(prometheus.CounterOpts{
	//	Name: "client_tcp_recovered_dead_conn",
	//	Help: "The total number of times that sending a query on a unresponsive/closed TCP conn succeeded eventually (by reopening/establishing a short-lived connection).",
	//}),
}

func (metrics *MetricsDef) IncSentUDPQueries(isIPv6 bool) {
	ip := "v4"
	if isIPv6 {
		ip = "v6"
	}

	metrics.QueriesSent.With(prometheus.Labels{"transport": "udp", "ip": ip}).Inc()
}

func (metrics *MetricsDef) IncSentTCPQueries(isIPv6 bool) {
	ip := "v4"
	if isIPv6 {
		ip = "v6"
	}
	metrics.QueriesSent.With(prometheus.Labels{"transport": "tcp", "ip": ip}).Inc()
}

func (metrics *MetricsDef) IncRecUDPQueries(isIPv6 bool) {
	ip := "v4"
	if isIPv6 {
		ip = "v6"
	}

	metrics.QueriesReceived.With(prometheus.Labels{"transport": "udp", "ip": ip}).Inc()
}

func (metrics *MetricsDef) IncRecTCPQueries(isIPv6 bool) {
	ip := "v4"
	if isIPv6 {
		ip = "v6"
	}
	metrics.QueriesReceived.With(prometheus.Labels{"transport": "tcp", "ip": ip}).Inc()
}

func RegisterMetrics(reg prometheus.Registerer) {
	val := reflect.ValueOf(M)
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)

		if v, ok := field.Interface().(prometheus.Collector); ok {
			reg.MustRegister(v)
		}
	}
}

func (m *MetricsDef) TrackResponse(rCode int, truncated bool, err error, stop bool) {
	if err != nil {
		rCode = -1
	}

	m.QueryResponses.With(prometheus.Labels{
		"rcode":     strconv.Itoa(rCode),
		"truncated": strconv.FormatBool(truncated),
		"isFinal":   strconv.FormatBool(stop),
		"hasErr":    strconv.FormatBool(err != nil),
	}).Inc()
}
