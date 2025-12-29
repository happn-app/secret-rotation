package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	RotationCount    *prometheus.CounterVec
	RotationDuration *prometheus.HistogramVec
	RotationErrorCount *prometheus.CounterVec
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		RotationCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "secret_rotation_count",
				Help: "Number of secret rotations processed.",
			},
			[]string{"handler", "secret_id"},
		),
		RotationDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "secret_rotation_duration_seconds",
				Help:    "Duration of secret rotation handling in seconds.",
				Buckets: prometheus.DefBuckets, // customize if rotations are usually fast/slow
			},
			[]string{"handler", "secret_id"},
		),
		RotationErrorCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "secret_rotation_error_count",
				Help: "Number of errors encountered during secret rotations.",
			},
			[]string{"error", "secret_id", "handler"},
		),
	}

	// Register metrics
	reg.MustRegister(m.RotationCount, m.RotationDuration)
	return m
}

func (m *Metrics) ObserveRotation(handler, secretID string, start time.Time, success bool) {
	// If you later want result label, add it to both metrics and pass it here.
	m.RotationCount.WithLabelValues(handler, secretID).Inc()
	m.RotationDuration.WithLabelValues(handler, secretID).Observe(time.Since(start).Seconds())
}

func Handler() http.Handler {
	return promhttp.Handler()
}
