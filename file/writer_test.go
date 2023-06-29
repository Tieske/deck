package file

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/kong/deck/state"
	"github.com/kong/go-kong/kong"
	"github.com/stretchr/testify/assert"
)

func captureOutput(f func()) string {
	reader, writer, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	stdout := os.Stdout
	stderr := os.Stderr
	defer func() {
		os.Stdout = stdout
		os.Stderr = stderr
	}()
	os.Stdout = writer
	os.Stderr = writer

	out := make(chan string)
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		var buf bytes.Buffer
		wg.Done()
		io.Copy(&buf, reader)
		out <- buf.String()
	}()
	wg.Wait()
	f()
	writer.Close()
	return <-out
}

func Test_compareOrder(t *testing.T) {
	tests := []struct {
		name      string
		sortable1 sortable
		sortable2 sortable
		expected  bool
	}{
		{
			sortable1: &FService{
				Service: kong.Service{
					Name: kong.String("my-service-1"),
					ID:   kong.String("my-id-1"),
				},
			},
			sortable2: &FService{
				Service: kong.Service{
					Name: kong.String("my-service-2"),
					ID:   kong.String("my-id-2"),
				},
			},
			expected: true,
		},

		{
			sortable1: &FRoute{
				Route: kong.Route{
					Name: kong.String("my-route-1"),
					ID:   kong.String("my-id-1"),
				},
			},
			sortable2: &FRoute{
				Route: kong.Route{
					Name: kong.String("my-route-2"),
					ID:   kong.String("my-id-2"),
				},
			},
			expected: true,
		},

		{
			sortable1: FUpstream{
				Upstream: kong.Upstream{
					Name: kong.String("my-upstream-1"),
					ID:   kong.String("my-id-1"),
				},
			},
			sortable2: FUpstream{
				Upstream: kong.Upstream{
					Name: kong.String("my-upstream-2"),
					ID:   kong.String("my-id-2"),
				},
			},
			expected: true,
		},

		{
			sortable1: FTarget{
				Target: kong.Target{
					Target: kong.String("my-target-1"),
					ID:     kong.String("my-id-1"),
				},
			},
			sortable2: FTarget{
				Target: kong.Target{
					Target: kong.String("my-target-2"),
					ID:     kong.String("my-id-2"),
				},
			},
			expected: true,
		},

		{
			sortable1: FCertificate{
				Cert: kong.String("my-certificate-1"),
				ID:   kong.String("my-id-1"),
			},
			sortable2: FCertificate{
				Cert: kong.String("my-certificate-2"),
				ID:   kong.String("my-id-2"),
			},
			expected: true,
		},

		{
			sortable1: FCACertificate{
				CACertificate: kong.CACertificate{
					Cert: kong.String("my-ca-certificate-1"),
					ID:   kong.String("my-id-1"),
				},
			},
			sortable2: FCACertificate{
				CACertificate: kong.CACertificate{
					Cert: kong.String("my-ca-certificate-2"),
					ID:   kong.String("my-id-2"),
				},
			},
			expected: true,
		},

		{
			sortable1: FPlugin{
				Plugin: kong.Plugin{
					Name: kong.String("my-plugin-1"),
					ID:   kong.String("my-id-1"),
				},
			},
			sortable2: FPlugin{
				Plugin: kong.Plugin{
					Name: kong.String("my-plugin-2"),
					ID:   kong.String("my-id-2"),
				},
			},
			expected: true,
		},

		{
			sortable1: &FConsumer{
				Consumer: kong.Consumer{
					Username: kong.String("my-consumer-1"),
					ID:       kong.String("my-id-2"),
				},
			},
			sortable2: &FConsumer{
				Consumer: kong.Consumer{
					Username: kong.String("my-consumer-2"),
					ID:       kong.String("my-id-2"),
				},
			},
			expected: true,
		},

		{
			sortable1: &FServicePackage{
				Name: kong.String("my-service-package-1"),
				ID:   kong.String("my-id-1"),
			},
			sortable2: &FServicePackage{
				Name: kong.String("my-service-package-2"),
				ID:   kong.String("my-id-2"),
			},
			expected: true,
		},
		{
			sortable1: &FServiceVersion{
				Version: kong.String("my-service-version-1"),
				ID:      kong.String("my-id-1"),
			},
			sortable2: &FServiceVersion{
				Version: kong.String("my-service-version-2"),
				ID:      kong.String("my-id-2"),
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if compareOrder(tt.sortable1, tt.sortable2) != tt.expected {
				t.Errorf("Expected %v, but isn't", tt.expected)
			}
		})
	}
}

func TestWriteKongStateToStdoutEmptyState(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	assert.Equal("-", filename)
	assert.NotEmpty(t, ks)
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Workspace:   "foo",
			Filename:    filename,
			FileFormat:  YAML,
			KongVersion: "2.8.0",
		})
	})
	assert.Equal("_format_version: \"1.1\"\n_workspace: foo\n", output)
	// JSON
	output = captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Workspace:   "foo",
			Filename:    filename,
			FileFormat:  JSON,
			KongVersion: "2.8.0",
		})
	})
	expected := `{
  "_format_version": "1.1",
  "_workspace": "foo"
}`
	assert.Equal(expected, output)
}

func TestWriteKongStateToStdoutStateWithOneService(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	var service state.Service
	service.ID = kong.String("first")
	service.Host = kong.String("example.com")
	service.Name = kong.String("my-service")
	ks.Services.Add(service)
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  YAML,
			KongVersion: "3.0.0",
		})
	})
	expected := fmt.Sprintf("_format_version: \"3.0\"\nservices:\n- host: %s\n  name: %s\n", *service.Host, *service.Name)
	assert.Equal(expected, output)
	// JSON
	output = captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Workspace:   "foo",
			Filename:    filename,
			FileFormat:  JSON,
			KongVersion: "3.0.0",
		})
	})
	expected = `{
  "_format_version": "3.0",
  "_workspace": "foo",
  "services": [
    {
      "host": "example.com",
      "name": "my-service"
    }
  ]
}`
	assert.Equal(expected, output)
}

func TestWriteKongStateToStdoutStateWithOneServiceOneRoute(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	var service state.Service
	service.ID = kong.String("first")
	service.Host = kong.String("example.com")
	service.Name = kong.String("my-service")
	ks.Services.Add(service)

	var route state.Route
	route.Name = kong.String("my-route")
	route.ID = kong.String("first")
	route.Hosts = kong.StringSlice("example.com", "demo.example.com")
	route.Service = &kong.Service{
		ID:   kong.String(*service.ID),
		Name: kong.String(*service.Name),
	}

	ks.Routes.Add(route)
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  YAML,
			KongVersion: "2.8.0",
		})
	})
	expected := fmt.Sprintf(`_format_version: "1.1"
services:
- host: %s
  name: %s
  routes:
  - hosts:
    - %s
    - %s
    name: %s
`, *service.Host, *service.Name, *route.Hosts[0], *route.Hosts[1], *route.Name)
	assert.Equal(expected, output)
	// JSON
	output = captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Workspace:   "foo",
			Filename:    filename,
			FileFormat:  JSON,
			KongVersion: "2.8.0",
		})
	})
	expected = `{
  "_format_version": "1.1",
  "_workspace": "foo",
  "services": [
    {
      "host": "example.com",
      "name": "my-service",
      "routes": [
        {
          "hosts": [
            "example.com",
            "demo.example.com"
          ],
          "name": "my-route"
        }
      ]
    }
  ]
}`
	assert.Equal(expected, output)
}

func Test_getFormatVersion(t *testing.T) {
	tests := []struct {
		name        string
		kongVersion string
		expected    string
		expectedErr string
		wantErr     bool
	}{
		{
			name:        "3.0.0 version",
			kongVersion: "3.0.0",
			expected:    "3.0",
		},
		{
			name:        "3.0.0.0 version",
			kongVersion: "3.0.0.0",
			expected:    "3.0",
		},
		{
			name:        "2.8.0 version",
			kongVersion: "2.8.0",
			expected:    "1.1",
		},
		{
			name:        "2.8.0.0 version",
			kongVersion: "2.8.0.0",
			expected:    "1.1",
		},
		{
			name:        "2.8.0.1-enterprise-edition version",
			kongVersion: "2.8.0.1-enterprise-edition",
			expected:    "1.1",
		},
		{
			name:        "unsupported version",
			kongVersion: "test",
			wantErr:     true,
			expectedErr: "parsing Kong version: unknown Kong version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := getFormatVersion(tt.kongVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error = %v, expected error = %v", err, tt.wantErr)
			}
			if tt.expectedErr != "" {
				assert.Equal(t, err.Error(), tt.expectedErr)
			}
			if res != tt.expected {
				t.Errorf("Expected %v, but isn't: %v", tt.expected, res)
			}
		})
	}
}

/*
 A consumer with an associated plugin of type key-auth and a key-auth credential
 should generate a KongConsumer with and associated KongPlugin and a secret with
 the key-auth key
*/
func TestWriteKongStateToKICStdoutStateWithOneConsumerKeyAuth(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var consumer state.Consumer
	consumer.ID = kong.String("my-consumer-id")
	consumer.Username = kong.String("my-consumer")
	consumer.CustomID = kong.String("my-custom-id")
	ks.Consumers.Add(consumer)

	var consumerPlugin state.Plugin
	consumerPlugin.ID = kong.String("consumer-plugin-id")
	consumerPlugin.Name = kong.String("key-auth")
	consumerPlugin.InstanceName = kong.String("key-auth-instance")
	consumerPlugin.Config = kong.Configuration{"key_names": []interface{}{"apikey"}}
	consumerPlugin.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
	ks.Plugins.Add(consumerPlugin)

	var keyAuth state.KeyAuth
	keyAuth.ID = kong.String("key-auth-id")
	keyAuth.Key = kong.String("key-auth-key")
	keyAuth.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
    ks.KeyAuths.Add(keyAuth)

	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"key-auth-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"key_names\": [\n        \"apikey\"\n      ]\n    },\n    \"plugin\": \"key-auth\"\n  }\n][\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"KeyAuth-\",\n      \"creationTimestamp\": null\n    },\n    \"stringData\": {\n      \"key\": \"key-auth-key\",\n      \"kongCredType\": \"key-auth\"\n    }\n  }\n][\n  {\n    \"kind\": \"KongConsumer\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-consumer\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"key-auth-instance\"\n      }\n    },\n    \"username\": \"my-consumer\",\n    \"custom_id\": \"my-custom-id\",\n    \"credentials\": [\n      \"KeyAuth-\"\n    ]\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	 A consumer with an associated plugin of type hmac-auth and a hmac-auth credential
	 should generate a KongConsumer with and associated KongPlugin and a secret with
	 the hmac-auth username and secret
*/
func TestWriteKongStateToKICStdoutStateWithOneConsumerHMACAuth(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var consumer state.Consumer
	consumer.ID = kong.String("my-consumer-id")
	consumer.Username = kong.String("my-consumer")
	consumer.CustomID = kong.String("my-custom-id")
	ks.Consumers.Add(consumer)

	var consumerPlugin state.Plugin
	consumerPlugin.ID = kong.String("consumer-plugin-id")
	consumerPlugin.Name = kong.String("hmac-auth")
	consumerPlugin.InstanceName = kong.String("hmac-auth-instance")
	consumerPlugin.Config = kong.Configuration{"hide_credentials": "false"}
	consumerPlugin.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
	ks.Plugins.Add(consumerPlugin)

	var hmacAuth state.HMACAuth
	hmacAuth.ID = kong.String("hmac-auth-id")
	hmacAuth.Username = kong.String("hmac-username")
	hmacAuth.Secret = kong.String("hmac-secret")
	hmacAuth.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
    ks.HMACAuths.Add(hmacAuth)

	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"hmac-auth-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"hide_credentials\": \"false\"\n    },\n    \"plugin\": \"hmac-auth\"\n  }\n][\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"HMACAuth-\",\n      \"creationTimestamp\": null\n    },\n    \"stringData\": {\n      \"kongCredType\": \"hmac-auth\",\n      \"secret\": \"hmac-secret\",\n      \"username\": \"hmac-username\"\n    }\n  }\n][\n  {\n    \"kind\": \"KongConsumer\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-consumer\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"hmac-auth-instance\"\n      }\n    },\n    \"username\": \"my-consumer\",\n    \"custom_id\": \"my-custom-id\",\n    \"credentials\": [\n      \"HMACAuth-\"\n    ]\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	 A consumer with an associated plugin of type jwt and a jwt credential
	 should generate a KongConsumer with and associated KongPlugin and a secret with
	 the jwt key and secret and algorithm
*/
func TestWriteKongStateToKICStdoutStateWithOneConsumerJWTAuth(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var consumer state.Consumer
	consumer.ID = kong.String("my-consumer-id")
	consumer.Username = kong.String("my-consumer")
	consumer.CustomID = kong.String("my-custom-id")
	ks.Consumers.Add(consumer)

	var consumerPlugin state.Plugin
	consumerPlugin.ID = kong.String("jwt-plugin-id")
	consumerPlugin.Name = kong.String("jwt")
	consumerPlugin.InstanceName = kong.String("jwt-instance")
	consumerPlugin.Config = kong.Configuration{"uri_param_names": []interface{}{"paramName_2.2.x"}}
	consumerPlugin.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
	ks.Plugins.Add(consumerPlugin)

	var jwtAuth state.JWTAuth
	jwtAuth.ID = kong.String("hmac-auth-id")
	jwtAuth.Secret = kong.String("C50k0bcahDhLNhLKSUBSR1OMiFGzNZ7X")
	jwtAuth.Key = kong.String("YJdmaDvVTJxtcWRCvkMikc8oELgAVNcz")
	jwtAuth.Algorithm = kong.String("HS256")
	jwtAuth.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
    ks.JWTAuths.Add(jwtAuth)

	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"jwt-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"uri_param_names\": [\n        \"paramName_2.2.x\"\n      ]\n    },\n    \"plugin\": \"jwt\"\n  }\n][\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"JWTAuth-\",\n      \"creationTimestamp\": null\n    },\n    \"stringData\": {\n      \"algorithm\": \"HS256\",\n      \"key\": \"YJdmaDvVTJxtcWRCvkMikc8oELgAVNcz\",\n      \"kongCredType\": \"jwt\",\n      \"secret\": \"C50k0bcahDhLNhLKSUBSR1OMiFGzNZ7X\"\n    }\n  }\n][\n  {\n    \"kind\": \"KongConsumer\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-consumer\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"jwt-instance\"\n      }\n    },\n    \"username\": \"my-consumer\",\n    \"custom_id\": \"my-custom-id\",\n    \"credentials\": [\n      \"JWTAuth-\"\n    ]\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	 A consumer with an associated plugin of type basic-auth and a basic-auth credential
	 should generate a KongConsumer with and associated KongPlugin and a secret with
	 the basic-auth username and password
*/
func TestWriteKongStateToKICStdoutStateWithOneConsumerBasicAuth(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var consumer state.Consumer
	consumer.ID = kong.String("my-consumer-id")
	consumer.Username = kong.String("my-consumer")
	consumer.CustomID = kong.String("my-custom-id")
	ks.Consumers.Add(consumer)

	var consumerPlugin state.Plugin
	consumerPlugin.ID = kong.String("basic-auth-plugin-id")
	consumerPlugin.Name = kong.String("basic-auth")
	consumerPlugin.InstanceName = kong.String("basic-auth-instance")
	consumerPlugin.Config = kong.Configuration{"hide_credentials": "true"}
	consumerPlugin.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
	ks.Plugins.Add(consumerPlugin)

	var basicAuth state.BasicAuth
	basicAuth.ID = kong.String("basic-auth-id")
	basicAuth.Username = kong.String("basic-auth-username")
	basicAuth.Password = kong.String("basic-auth-password")
	basicAuth.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
    ks.BasicAuths.Add(basicAuth)

	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"basic-auth-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"hide_credentials\": \"true\"\n    },\n    \"plugin\": \"basic-auth\"\n  }\n][\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"BasicAuth-\",\n      \"creationTimestamp\": null\n    },\n    \"stringData\": {\n      \"kongCredType\": \"basic-auth\",\n      \"password\": \"basic-auth-password\",\n      \"username\": \"basic-auth-username\"\n    }\n  }\n][\n  {\n    \"kind\": \"KongConsumer\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-consumer\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"basic-auth-instance\"\n      }\n    },\n    \"username\": \"my-consumer\",\n    \"custom_id\": \"my-custom-id\",\n    \"credentials\": [\n      \"BasicAuth-\"\n    ]\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	 A consumer with an associated plugin of type Oauth2 and a Oauth2 credential
	 should generate a KongConsumer with and associated KongPlugin and a secret with
	 client id, client secret, redirect uris, client type, and hash secret.	 
*/
func TestWriteKongStateToKICStdoutStateWithOneConsumerOauth2Credential(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var consumer state.Consumer
	consumer.ID = kong.String("my-consumer-id")
	consumer.Username = kong.String("my-consumer")
	consumer.CustomID = kong.String("my-custom-id")
	ks.Consumers.Add(consumer)

	var consumerPlugin state.Plugin
	consumerPlugin.ID = kong.String("oauth2-plugin-id")
	consumerPlugin.Name = kong.String("oauth2")
	consumerPlugin.InstanceName = kong.String("oauth2-instance")
	consumerPlugin.Config = kong.Configuration{"scopes": []interface{}{"email", "phone", "address"}, 
	"mandatory_scope": "true", "token_expiration": 7200, "enable_authorization_code": "true",}
	consumerPlugin.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
	ks.Plugins.Add(consumerPlugin)

	var oauth2Auth state.Oauth2Credential
	oauth2Auth.ID = kong.String("oauth-id")
	oauth2Auth.Name = kong.String("oauth-name")
	oauth2Auth.ClientID = kong.String("oauth-client-id")
	oauth2Auth.ClientSecret = kong.String("oauth-client-secret")
	oauth2Auth.RedirectURIs = kong.StringSlice("http://example.com/callback")
	oauth2Auth.ClientType = kong.String("confidential")
	oauth2Auth.HashSecret = kong.Bool(false)
	oauth2Auth.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
    ks.Oauth2Creds.Add(oauth2Auth)

	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"oauth2-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"enable_authorization_code\": \"true\",\n      \"mandatory_scope\": \"true\",\n      \"scopes\": [\n        \"email\",\n        \"phone\",\n        \"address\"\n      ],\n      \"token_expiration\": 7200\n    },\n    \"plugin\": \"oauth2\"\n  }\n][\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"OAuth2Cred-\",\n      \"creationTimestamp\": null\n    },\n    \"stringData\": {\n      \"client_id\": \"oauth-client-id\",\n      \"client_secret\": \"oauth-client-secret\",\n      \"client_type\": \"confidential\",\n      \"hash_secret\": \"false\",\n      \"kongCredType\": \"oauth2\"\n    }\n  }\n][\n  {\n    \"kind\": \"KongConsumer\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-consumer\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"oauth2-instance\"\n      }\n    },\n    \"username\": \"my-consumer\",\n    \"custom_id\": \"my-custom-id\",\n    \"credentials\": [\n      \"OAuth2Cred-\"\n    ]\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	A consumer with an associated plugin of type ACL and an ACL group
	should generate a KongConsumer with and associated KongPlugin and a KongACLGroup
	with the ACL group name and  ACL group id.
*/
func TestWriteKongStateToKICStdoutStateWithOneConsumerACLGroup(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var consumer state.Consumer
	consumer.ID = kong.String("my-consumer-id")
	consumer.Username = kong.String("my-consumer")
	consumer.CustomID = kong.String("my-custom-id")
	ks.Consumers.Add(consumer)

	var consumerPlugin state.Plugin
	consumerPlugin.ID = kong.String("acl-plugin-id")
	consumerPlugin.Name = kong.String("acl")
	consumerPlugin.InstanceName = kong.String("acl-instance")
	consumerPlugin.Config = kong.Configuration{"allow": []interface{}{"admin-group", "retail-group", "banking-group"}}
	consumerPlugin.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
	ks.Plugins.Add(consumerPlugin)

	var aclGroup state.ACLGroup
	aclGroup.ID = kong.String("acl-id")
	aclGroup.Group = kong.String("admin-group")
	aclGroup.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
    ks.ACLGroups.Add(aclGroup)

	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"acl-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"allow\": [\n        \"admin-group\",\n        \"retail-group\",\n        \"banking-group\"\n      ]\n    },\n    \"plugin\": \"acl\"\n  }\n][\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"ACLGroup-\",\n      \"creationTimestamp\": null\n    },\n    \"stringData\": {\n      \"group\": \"admin-group\",\n      \"kongCredType\": \"acl\"\n    }\n  }\n][\n  {\n    \"kind\": \"KongConsumer\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-consumer\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"acl-instance\"\n      }\n    },\n    \"username\": \"my-consumer\",\n    \"custom_id\": \"my-custom-id\",\n    \"credentials\": [\n      \"ACLGroup-\"\n    ]\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	A consumer with an associated plugin of type MTLS Auth and MTLSAuth credentials
	should generate a KongConsumer with and associated KongPlugin and a secret
	with the MTLSAuth certificate details.
*/
func TestWriteKongStateToKICStdoutStateWithOneConsumerMTLSAuth(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var consumer state.Consumer
	consumer.ID = kong.String("my-consumer-id")
	consumer.Username = kong.String("my-consumer")
	consumer.CustomID = kong.String("my-custom-id")
	ks.Consumers.Add(consumer)

	var consumerPlugin state.Plugin
	consumerPlugin.ID = kong.String("mtls-auth-plugin-id")
	consumerPlugin.Name = kong.String("mtls-auth")
	consumerPlugin.InstanceName = kong.String("mtls-auth-instance")
	consumerPlugin.Config = kong.Configuration{"ca_certificates": []interface{}{"fdac360e-7b19-4ade-a553-6dd22937c82f"}, 
	"http_proxy_host": "example", "http_proxy_port": 80}
	consumerPlugin.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
	ks.Plugins.Add(consumerPlugin)

	var mtlsAuth state.MTLSAuth
	var cacert kong.CACertificate

	// initialize CACertificate
	cacert.ID = kong.String("fdac360e-7b19-4ade-a553-6dd22937c82f")
	cacert.Cert = kong.String("-----BEGIN CERTIFICATE-----\nMIICATCCAWoCCQDZq7X6Z3Qz7TANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJV\nUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCUNpdHkgQnVzaW5lc3MxDTALBgNVBAoM\nBE9yZzEUMBIGA1UECwwLU2VjdXJpdHkgQ0ExGDAWBgNVBAMMD2V4YW1wbGUuY29t\nMB4XDTIwMDUyNzE5MjY0MVoXDTIxMDUyNjE5MjY0MVowRTELMAkGA1UEBhMCVVMx\nCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlDaXR5IEJ1c2luZXNzMQ0wCwYDVQQKDARP\ncmcxFDASBgNVBAsMC1NlY3VyaXR5IENBMRowGAYDVQQDDB9leGFtcGxlLmNvbSAt\nIE9yZzEwWTATBg-----END CERTIFICATE-----")
	cacert.CertDigest = kong.String("2ZXt/8T161gL9mW1UlORjjXBnp/v1gtHausPyeQJiWw=")
	mtlsAuth.ID = kong.String("acl-id")
	mtlsAuth.SubjectName = kong.String("CN=example.com,OU=OrgUnit,O=Org,L=City,ST=State,C=US")
	mtlsAuth.CACertificate =  &cacert
	mtlsAuth.Consumer = &kong.Consumer{
		ID: kong.String(*consumer.ID),
		Username: kong.String(*consumer.Username),
	}
    ks.MTLSAuths.Add(mtlsAuth)

	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"mtls-auth-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"ca_certificates\": [\n        \"fdac360e-7b19-4ade-a553-6dd22937c82f\"\n      ],\n      \"http_proxy_host\": \"example\",\n      \"http_proxy_port\": 80\n    },\n    \"plugin\": \"mtls-auth\"\n  }\n][\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"MTLSAuth-\",\n      \"creationTimestamp\": null,\n      \"labels\": {\n        \"konghq.com/ca-cert\": \"true\"\n      },\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"stringData\": {\n      \"cert\": \"-----BEGIN CERTIFICATE-----\\nMIICATCCAWoCCQDZq7X6Z3Qz7TANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJV\\nUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCUNpdHkgQnVzaW5lc3MxDTALBgNVBAoM\\nBE9yZzEUMBIGA1UECwwLU2VjdXJpdHkgQ0ExGDAWBgNVBAMMD2V4YW1wbGUuY29t\\nMB4XDTIwMDUyNzE5MjY0MVoXDTIxMDUyNjE5MjY0MVowRTELMAkGA1UEBhMCVVMx\\nCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlDaXR5IEJ1c2luZXNzMQ0wCwYDVQQKDARP\\ncmcxFDASBgNVBAsMC1NlY3VyaXR5IENBMRowGAYDVQQDDB9leGFtcGxlLmNvbSAt\\nIE9yZzEwWTATBg-----END CERTIFICATE-----\",\n      \"cert_digest\": \"2ZXt/8T161gL9mW1UlORjjXBnp/v1gtHausPyeQJiWw=\",\n      \"id\": \"fdac360e-7b19-4ade-a553-6dd22937c82f\",\n      \"kongCredType\": \"mtls-auth\",\n      \"subject_name\": \"CN=example.com,OU=OrgUnit,O=Org,L=City,ST=State,C=US\"\n    },\n    \"type\": \"Opaque\"\n  }\n][\n  {\n    \"kind\": \"KongConsumer\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-consumer\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"mtls-auth-instance\"\n      }\n    },\n    \"username\": \"my-consumer\",\n    \"custom_id\": \"my-custom-id\",\n    \"credentials\": [\n      \"MTLSAuth-\"\n    ]\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	Generate a service with a plugin and two routes with their own plugins.
	The service generates a k8s service and a plugin associated to it via annotation.
	The routes generates a k8s ingress and a KongIngress associated to it via annotation.
	The routes plugin generates a KongPlugin associated to it via annotation.
*/
func TestWriteKongStateToKICStdoutStateWithTwoRoutes(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	// service
	var service state.Service
	service.ID = kong.String("my-service-id")
	service.Name = kong.String("my-service")
	service.Port = kong.Int(8888)
	ks.Services.Add(service)

	// service servicePlugin
	var servicePlugin state.Plugin
	servicePlugin.ID = kong.String("OAS3-Validator-id")
	servicePlugin.Name = kong.String("oas-validation")
	servicePlugin.InstanceName = kong.String("oas-validation-instance")
	servicePlugin.Config = kong.Configuration{"api_spec": "openapi..."}
	servicePlugin.Service = &kong.Service{
		ID: kong.String(*service.ID),
		Name: kong.String(*service.Name),
	}
	ks.Plugins.Add(servicePlugin)

	// first route
	var route1 state.Route
	route1.Name = kong.String("route1-name")
	route1.Hosts = kong.StringSlice("host1.kong.lan")
	route1.Paths = kong.StringSlice("/my-first-path")
	route1.ID = kong.String("route1-id")
	route1.Protocols = kong.StringSlice("http", "https")
	route1.Methods = kong.StringSlice("GET", "POST")
	route1.StripPath = kong.Bool(true)
	route1.PreserveHost = kong.Bool(false)
	route1.Service = &kong.Service{
		ID: kong.String(*service.ID),
		Name: kong.String(*service.Name),
	}
    ks.Routes.Add(route1)
	
	// first route Plugin
	var firstRoutePlugin state.Plugin
	firstRoutePlugin.ID = kong.String("my-firstRoutePlugin-id")
	firstRoutePlugin.Name = kong.String("response-transformer")
	firstRoutePlugin.InstanceName = kong.String("response-transformer-instance")
	firstRoutePlugin.Config = kong.Configuration{"add": "config-value"}
	firstRoutePlugin.Route = &kong.Route{
		ID: kong.String(*route1.ID),
		Name: kong.String(*route1.Name),
	}
	ks.Plugins.Add(firstRoutePlugin)

	// second route
	var route2 state.Route
	route2.Name = kong.String("route2-name")
	route2.Hosts = kong.StringSlice("host1.kong.lan")
	route2.Paths = kong.StringSlice("/my-second-path")
	route2.ID = kong.String("route2-id")
	route2.RegexPriority = kong.Int(0)
	route2.Protocols = kong.StringSlice("http", "https")
	route2.Methods = kong.StringSlice("GET", "POST")
	route2.StripPath = kong.Bool(true)
	route2.PreserveHost = kong.Bool(false)
	route2.ResponseBuffering = kong.Bool(true)
	route2.Service = &kong.Service{
		ID: kong.String(*service.ID),
		Name: kong.String(*service.Name),
	}
    ks.Routes.Add(route2)

	// second route Plugin
	var secondRoutePlugin state.Plugin
	secondRoutePlugin.ID = kong.String("my-secondRoutePlugin-id")
	secondRoutePlugin.Name = kong.String("request-transformer")
	secondRoutePlugin.InstanceName = kong.String("request-transformer-instance")
	secondRoutePlugin.Config = kong.Configuration{"add": "config-value"}
	secondRoutePlugin.Route = &kong.Route{
		ID: kong.String(*route2.ID),
		Name: kong.String(*route2.Name),
	}
	ks.Plugins.Add(secondRoutePlugin)
	
	// KIC output
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongIngress\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"route1-name\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"route\": {\n      \"methods\": [\n        \"GET\",\n        \"POST\"\n      ],\n      \"protocols\": [\n        \"http\",\n        \"https\"\n      ],\n      \"strip_path\": true,\n      \"preserve_host\": false\n    }\n  },\n  {\n    \"kind\": \"KongIngress\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"route2-name\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"route\": {\n      \"methods\": [\n        \"GET\",\n        \"POST\"\n      ],\n      \"protocols\": [\n        \"http\",\n        \"https\"\n      ],\n      \"regex_priority\": 0,\n      \"strip_path\": true,\n      \"preserve_host\": false,\n      \"response_buffering\": true\n    }\n  }\n][\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"response-transformer-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"add\": \"config-value\"\n    },\n    \"plugin\": \"response-transformer\"\n  },\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"request-transformer-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"add\": \"config-value\"\n    },\n    \"plugin\": \"request-transformer\"\n  },\n  {\n    \"kind\": \"KongPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"oas-validation-instance\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"api_spec\": \"openapi...\"\n    },\n    \"plugin\": \"oas-validation\"\n  }\n][\n  {\n    \"kind\": \"Ingress\",\n    \"apiVersion\": \"networking.k8s.io/v1\",\n    \"metadata\": {\n      \"name\": \"route1-name\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/override\": \"route1-name\",\n        \"konghq.com/plugins\": \"response-transformer-instance\"\n      }\n    },\n    \"spec\": {\n      \"rules\": [\n        {\n          \"host\": \"host1.kong.lan\",\n          \"http\": {\n            \"paths\": [\n              {\n                \"path\": \"/my-first-path\",\n                \"pathType\": null,\n                \"backend\": {\n                  \"service\": {\n                    \"name\": \"my-service\",\n                    \"port\": {\n                      \"number\": 8888\n                    }\n                  }\n                }\n              }\n            ]\n          }\n        }\n      ]\n    },\n    \"status\": {\n      \"loadBalancer\": {}\n    }\n  },\n  {\n    \"kind\": \"Ingress\",\n    \"apiVersion\": \"networking.k8s.io/v1\",\n    \"metadata\": {\n      \"name\": \"route2-name\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/override\": \"route2-name\",\n        \"konghq.com/plugins\": \"request-transformer-instance\"\n      }\n    },\n    \"spec\": {\n      \"rules\": [\n        {\n          \"host\": \"host1.kong.lan\",\n          \"http\": {\n            \"paths\": [\n              {\n                \"path\": \"/my-second-path\",\n                \"pathType\": null,\n                \"backend\": {\n                  \"service\": {\n                    \"name\": \"my-service\",\n                    \"port\": {\n                      \"number\": 8888\n                    }\n                  }\n                }\n              }\n            ]\n          }\n        }\n      ]\n    },\n    \"status\": {\n      \"loadBalancer\": {}\n    }\n  }\n][\n  {\n    \"kind\": \"Service\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"my-service\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/plugins\": \"oas-validation-instance\"\n      }\n    },\n    \"spec\": {\n      \"ports\": [\n        {\n          \"protocol\": \"TCP\",\n          \"port\": 8888,\n          \"targetPort\": 8888\n        }\n      ],\n      \"selector\": {\n        \"app\": \"my-service\"\n      }\n    },\n    \"status\": {\n      \"loadBalancer\": {}\n    }\n  }\n]}")
	assert.Equal(expected, output)
}

/*
  Two kong services generate two Kubernetes services
*/
func TestWriteKongStateToKICStdoutStateWithTwoServices(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var service1 state.Service
	service1.ID = kong.String("my-service-id1")
	service1.Name = kong.String("my-service1")
	service1.Port = kong.Int(1025)
	service1.Protocol = kong.String("TCP")
	ks.Services.Add(service1)

	var service2 state.Service
	service2.ID = kong.String("my-service-id2")
	service2.Name = kong.String("my-service2")
	service2.Port = kong.Int(1125)
	service2.Protocol = kong.String("UDP")
	ks.Services.Add(service2)
	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"Service\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"my-service1\",\n      \"creationTimestamp\": null\n    },\n    \"spec\": {\n      \"ports\": [\n        {\n          \"protocol\": \"TCP\",\n          \"port\": 1025,\n          \"targetPort\": 1025\n        }\n      ],\n      \"selector\": {\n        \"app\": \"my-service1\"\n      }\n    },\n    \"status\": {\n      \"loadBalancer\": {}\n    }\n  },\n  {\n    \"kind\": \"Service\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"my-service2\",\n      \"creationTimestamp\": null\n    },\n    \"spec\": {\n      \"ports\": [\n        {\n          \"protocol\": \"UDP\",\n          \"port\": 1125,\n          \"targetPort\": 1125\n        }\n      ],\n      \"selector\": {\n        \"app\": \"my-service2\"\n      }\n    },\n    \"status\": {\n      \"loadBalancer\": {}\n    }\n  }\n]}")
	assert.Equal(expected, output)
}


/*
	A service with additional fields generate a Kubernetes service and a KongIngress resource
	with the additional fields in the proxy section.
	An upstream whose name is the same as the service host populates the upstream section of
	the same KongIngress resource.
	The service resource is annotated to be associated with the KongIngress resource.
*/
func TestWriteKongStateToKICStdoutStateWithServiceAndUpstream(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var service1 state.Service
	service1.ID = kong.String("my-service-id1")
	service1.Name = kong.String("my-service1")
	service1.Port = kong.Int(1025)
	service1.Protocol = kong.String("TCP")
	service1.Host = kong.String("my-service1.kong.lan")
	service1.ConnectTimeout = kong.Int(1000)
	service1.ReadTimeout = kong.Int(1000)
	service1.WriteTimeout = kong.Int(1000)
	service1.Retries = kong.Int(5)
	ks.Services.Add(service1)

	// upstream is associated with service when service.Host == upstream.Name
	var upstream1 state.Upstream
	upstream1.ID = kong.String("my-upstream-id1")
	upstream1.Name = kong.String("my-service1.kong.lan")
	upstream1.HashOn = kong.String("header")
	upstream1.HashOnHeader = kong.String("x-lb")
	upstream1.HashFallback = kong.String("ip")
	upstream1.Algorithm = kong.String("consistent-hashing")
	ks.Upstreams.Add(upstream1)
	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongIngress\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"my-service1.kong.lan\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"upstream\": {\n      \"algorithm\": \"consistent-hashing\",\n      \"hash_on\": \"header\",\n      \"hash_fallback\": \"ip\",\n      \"hash_on_header\": \"x-lb\"\n    },\n    \"proxy\": {\n      \"protocol\": \"TCP\",\n      \"retries\": 5,\n      \"connect_timeout\": 1000,\n      \"read_timeout\": 1000,\n      \"write_timeout\": 1000\n    }\n  }\n][\n  {\n    \"kind\": \"Service\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"my-service1\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"konghq.com/override\": \"my-service1.kong.lan\"\n      }\n    },\n    \"spec\": {\n      \"ports\": [\n        {\n          \"protocol\": \"TCP\",\n          \"port\": 1025,\n          \"targetPort\": 1025\n        }\n      ],\n      \"selector\": {\n        \"app\": \"my-service1\"\n      }\n    },\n    \"status\": {\n      \"loadBalancer\": {}\n    }\n  }\n]}")
	assert.Equal(expected, output)
}

/*
	Two plugin definitions generate two KongClusterPlugin resources.
*/
func TestWriteKongStateToKICStdoutStateWithTwoClusterPlugins(t *testing.T) {
	ks, _ := state.NewKongState()
	filename := "-"
	assert := assert.New(t)
	
	var plugin state.Plugin
	plugin.ID = kong.String("my-plugin-id")
	plugin.Name = kong.String("response-transformer")
	plugin.InstanceName = kong.String("instance-UUID")
	plugin.Config = kong.Configuration{"add": "config-value"}
	ks.Plugins.Add(plugin)

	var plugin2 state.Plugin
	plugin2.ID = kong.String("my-plugin-id2")
	plugin2.Name = kong.String("request-transformer")
	plugin2.InstanceName = kong.String("instance-UUID")
	plugin2.Config = kong.Configuration{"add": "config-value"}
	ks.Plugins.Add(plugin2)
	
	// YAML
	output := captureOutput(func() {
		KongStateToFile(ks, WriteConfig{
			Filename:    filename,
			FileFormat:  KIC,
			KongVersion: "2.10.0",
			WithID: true,
		})
	})
	expected := fmt.Sprintf("{[\n  {\n    \"kind\": \"KongClusterPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"instance-UUID\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"add\": \"config-value\"\n    },\n    \"plugin\": \"request-transformer\"\n  },\n  {\n    \"kind\": \"KongClusterPlugin\",\n    \"apiVersion\": \"configuration.konghq.com/v1\",\n    \"metadata\": {\n      \"name\": \"instance-UUID\",\n      \"creationTimestamp\": null,\n      \"annotations\": {\n        \"kubernetes.io/ingress.class\": \"kong\"\n      }\n    },\n    \"config\": {\n      \"add\": \"config-value\"\n    },\n    \"plugin\": \"response-transformer\"\n  }\n]}")
	assert.Equal(expected, output)
}