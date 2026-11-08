package saml

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// artifactMetadataWithServices returns IdP metadata publishing the given artifact resolution
// services. | artifactMetadataWithServices 返回发布给定工件解析服务的 IdP 元数据。
func artifactMetadataWithServices(services ...IndexedEndpoint) *EntityDescriptor {
	metadata := testMetadata()
	metadata.IDPSSODescriptor.ArtifactResolutionService = services
	return metadata
}

// artifactTestArtifact returns a valid SAMLart targeting endpoint index 0. | artifactTestArtifact 返回
// 指向端点索引 0 的合法 SAMLart。
func artifactTestArtifact(t *testing.T) string {
	t.Helper()
	artifact, err := NewArtifact(0, [ArtifactSourceIDSize]byte{1})
	if err != nil {
		t.Fatalf("NewArtifact: %v", err)
	}
	return artifact.String()
}

// artifactSuccessHandler serves a success ArtifactResponse and counts calls. |
// artifactSuccessHandler 提供成功 ArtifactResponse 并统计调用次数。
func artifactSuccessHandler(calls *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		response, version, ok := artifactResolutionResponseBody(body)
		if !ok {
			http.Error(w, "bad artifact resolve", http.StatusBadRequest)
			return
		}
		writeSOAPPayloadVersion(w, version, response)
	}
}

// artifactFaultHandler serves a SOAP fault and counts calls. | artifactFaultHandler 提供 SOAP 异常并
// 统计调用次数。
func artifactFaultHandler(calls *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		writeSOAPFault(w, http.StatusInternalServerError, "soap:Server", "endpoint failed")
	}
}

// artifactErrorHandler serves a non-SOAP failure and counts calls. | artifactErrorHandler 提供非 SOAP
// 失败并统计调用次数。
func artifactErrorHandler(calls *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

// TestArtifactResolutionFailover covers endpoint failover, aggregation, limits and total timeouts. |
// TestArtifactResolutionFailover 覆盖端点故障转移、聚合、限制与总超时。
func TestArtifactResolutionFailover(t *testing.T) {
	t.Run("second endpoint succeeds after the first fails", func(t *testing.T) {
		var primaryCalls, secondaryCalls atomic.Int32
		primary := httptest.NewServer(artifactFaultHandler(&primaryCalls))
		defer primary.Close()
		secondary := httptest.NewServer(artifactSuccessHandler(&secondaryCalls))
		defer secondary.Close()
		sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
			config.IDPMetadata = artifactMetadataWithServices(
				IndexedEndpoint{Binding: BindingSOAP, Location: primary.URL, Index: 0},
				IndexedEndpoint{Binding: BindingSOAP, Location: secondary.URL, Index: 1},
			)
		})
		raw, err := sp.resolveArtifact(context.Background(), artifactTestArtifact(t))
		if err != nil {
			var aggregate *ArtifactResolutionError
			if errors.As(err, &aggregate) {
				for _, attempt := range aggregate.Attempts {
					t.Logf("attempt %d %s: %v", attempt.Index, attempt.URL, attempt.Err)
				}
			}
			t.Fatalf("resolveArtifact: %v", err)
		}
		if !strings.Contains(string(raw), "embedded-response") {
			t.Fatalf("resolved response = %s", raw)
		}
		if primaryCalls.Load() != 1 || secondaryCalls.Load() != 1 {
			t.Fatalf("calls = %d, %d", primaryCalls.Load(), secondaryCalls.Load())
		}
	})

	t.Run("all endpoints fail with an aggregate error", func(t *testing.T) {
		var faultCalls, errorCalls atomic.Int32
		faultServer := httptest.NewServer(artifactFaultHandler(&faultCalls))
		defer faultServer.Close()
		errorServer := httptest.NewServer(artifactErrorHandler(&errorCalls))
		defer errorServer.Close()
		sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
			config.IDPMetadata = artifactMetadataWithServices(
				IndexedEndpoint{Binding: BindingSOAP, Location: faultServer.URL, Index: 0},
				IndexedEndpoint{Binding: BindingSOAP, Location: errorServer.URL, Index: 1},
			)
		})
		_, err := sp.resolveArtifact(context.Background(), artifactTestArtifact(t))
		var aggregate *ArtifactResolutionError
		if !errors.As(err, &aggregate) {
			t.Fatalf("error = %v, want *ArtifactResolutionError", err)
		}
		if len(aggregate.Attempts) != 2 {
			t.Fatalf("attempts = %+v", aggregate.Attempts)
		}
		if aggregate.Attempts[0].Index != 0 || aggregate.Attempts[0].URL != faultServer.URL {
			t.Fatalf("first attempt = %+v", aggregate.Attempts[0])
		}
		if aggregate.Attempts[1].Index != 1 || aggregate.Attempts[1].URL != errorServer.URL {
			t.Fatalf("second attempt = %+v", aggregate.Attempts[1])
		}
		if !errors.Is(err, ErrSOAPFault) || !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("aggregate error = %v", err)
		}
		if faultCalls.Load() != 1 || errorCalls.Load() != 1 {
			t.Fatalf("calls = %d, %d", faultCalls.Load(), errorCalls.Load())
		}
	})

	t.Run("configured endpoint limit truncates candidates", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(artifactFaultHandler(&calls))
		defer server.Close()
		services := make([]IndexedEndpoint, 0, 10)
		for index := 0; index < 10; index++ {
			services = append(services, IndexedEndpoint{
				Binding:  BindingSOAP,
				Location: server.URL + "/ars/" + strconv.Itoa(index),
				Index:    index,
			})
		}
		sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
			config.IDPMetadata = artifactMetadataWithServices(services...)
			config.ArtifactResolutionMaxEndpoints = 3
		})
		_, err := sp.resolveArtifact(context.Background(), artifactTestArtifact(t))
		var aggregate *ArtifactResolutionError
		if !errors.As(err, &aggregate) {
			t.Fatalf("error = %v, want *ArtifactResolutionError", err)
		}
		if len(aggregate.Attempts) != 3 || calls.Load() != 3 {
			t.Fatalf("attempts = %d, calls = %d", len(aggregate.Attempts), calls.Load())
		}
	})

	t.Run("default endpoint limit is applied", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(artifactFaultHandler(&calls))
		defer server.Close()
		services := make([]IndexedEndpoint, 0, DefaultArtifactResolutionMaxEndpoints+2)
		for index := 0; index < DefaultArtifactResolutionMaxEndpoints+2; index++ {
			services = append(services, IndexedEndpoint{
				Binding:  BindingSOAP,
				Location: server.URL + "/ars/" + strconv.Itoa(index),
				Index:    index,
			})
		}
		sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
			config.IDPMetadata = artifactMetadataWithServices(services...)
		})
		_, err := sp.resolveArtifact(context.Background(), artifactTestArtifact(t))
		var aggregate *ArtifactResolutionError
		if !errors.As(err, &aggregate) {
			t.Fatalf("error = %v, want *ArtifactResolutionError", err)
		}
		if len(aggregate.Attempts) != DefaultArtifactResolutionMaxEndpoints || calls.Load() != DefaultArtifactResolutionMaxEndpoints {
			t.Fatalf("attempts = %d, calls = %d", len(aggregate.Attempts), calls.Load())
		}
	})

	t.Run("total timeout aborts hanging endpoints", func(t *testing.T) {
		unblock := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-unblock:
			}
		}))
		defer server.Close()
		defer close(unblock)
		sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
			config.IDPMetadata = artifactMetadataWithServices(
				IndexedEndpoint{Binding: BindingSOAP, Location: server.URL + "/hang/0", Index: 0},
				IndexedEndpoint{Binding: BindingSOAP, Location: server.URL + "/hang/1", Index: 1},
			)
			config.ArtifactResolutionTimeout = 100 * time.Millisecond
			config.ArtifactResolutionTotalTimeout = 250 * time.Millisecond
		})
		started := time.Now()
		_, err := sp.resolveArtifact(context.Background(), artifactTestArtifact(t))
		elapsed := time.Since(started)
		var aggregate *ArtifactResolutionError
		if !errors.As(err, &aggregate) {
			t.Fatalf("error = %v, want *ArtifactResolutionError", err)
		}
		if len(aggregate.Attempts) == 0 || len(aggregate.Attempts) > 2 {
			t.Fatalf("attempts = %d", len(aggregate.Attempts))
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want context deadline exceeded", err)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("resolution took %s", elapsed)
		}
	})
}

// TestArtifactResolutionConfigValidation checks artifact resolution configuration defaults and
// bounds. | TestArtifactResolutionConfigValidation 校验工件解析配置的默认值与边界。
func TestArtifactResolutionConfigValidation(t *testing.T) {
	base := func() ServiceProviderConfig {
		return ServiceProviderConfig{
			EntityID:    artifactSPEntity,
			ACSURL:      artifactACSURL,
			IDPMetadata: artifactMetadata("https://idp.example/saml/artifact"),
		}
	}
	cases := []struct {
		name   string
		mutate func(*ServiceProviderConfig)
	}{
		{name: "negative endpoint limit", mutate: func(config *ServiceProviderConfig) {
			config.ArtifactResolutionMaxEndpoints = -1
		}},
		{name: "endpoint limit above hard cap", mutate: func(config *ServiceProviderConfig) {
			config.ArtifactResolutionMaxEndpoints = MaxArtifactResolutionEndpoints + 1
		}},
		{name: "unsupported SOAP version", mutate: func(config *ServiceProviderConfig) {
			config.ArtifactSOAPVersion = SOAPVersion("1.0")
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			config := base()
			test.mutate(&config)
			if _, err := NewServiceProvider(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
	sp, err := NewServiceProvider(base())
	if err != nil {
		t.Fatalf("NewServiceProvider: %v", err)
	}
	config := sp.Config()
	if config.ArtifactSOAPVersion != SOAPVersion11 {
		t.Fatalf("default SOAP version = %q", config.ArtifactSOAPVersion)
	}
	if config.ArtifactResolutionMaxEndpoints != DefaultArtifactResolutionMaxEndpoints {
		t.Fatalf("default max endpoints = %d", config.ArtifactResolutionMaxEndpoints)
	}
	if config.ArtifactResolutionTimeout != 10*time.Second || config.ArtifactResolutionTotalTimeout != 30*time.Second {
		t.Fatalf("default timeouts = %s, %s", config.ArtifactResolutionTimeout, config.ArtifactResolutionTotalTimeout)
	}
	upper := base()
	upper.ArtifactResolutionMaxEndpoints = MaxArtifactResolutionEndpoints
	upper.ArtifactSOAPVersion = SOAPVersion12
	upper.ArtifactResolutionTotalTimeout = 2 * time.Second
	sp, err = NewServiceProvider(upper)
	if err != nil {
		t.Fatalf("NewServiceProvider upper bounds: %v", err)
	}
	config = sp.Config()
	if config.ArtifactResolutionMaxEndpoints != MaxArtifactResolutionEndpoints || config.ArtifactSOAPVersion != SOAPVersion12 {
		t.Fatalf("config = %+v", config)
	}
	if config.ArtifactResolutionTotalTimeout != 2*time.Second {
		t.Fatalf("total timeout = %s", config.ArtifactResolutionTotalTimeout)
	}
}
