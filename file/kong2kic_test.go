package file

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_convertKongGatewayToIngress(t *testing.T) {
	type args struct {
		inputFilename  string
		outputFilename string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "convert one service",
			args: args{
				inputFilename:  "testdata/kong2kic/1-service/input.yaml",
				outputFilename: "testdata/kong2kic/1-service/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service and one route",
			args: args{
				inputFilename:  "testdata/kong2kic/2-service-and-route/input.yaml",
				outputFilename: "testdata/kong2kic/2-service-and-route/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream data",
			args: args{
				inputFilename:  "testdata/kong2kic/3-service-and-upstream/input.yaml",
				outputFilename: "testdata/kong2kic/3-service-and-upstream/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream and route",
			args: args{
				inputFilename:  "testdata/kong2kic/4-service-route-upstream/input.yaml",
				outputFilename: "testdata/kong2kic/4-service-route-upstream/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route, acl auth plugin",
			args: args{
				inputFilename:  "testdata/kong2kic/5-service-route-upstream-acl-auth/input.yaml",
				outputFilename: "testdata/kong2kic/5-service-route-upstream-acl-auth/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route, basic auth plugin",
			args: args{
				inputFilename:  "testdata/kong2kic/6-service-route-upstream-basic-auth/input.yaml",
				outputFilename: "testdata/kong2kic/6-service-route-upstream-basic-auth/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route, jwt auth plugin",
			args: args{
				inputFilename:  "testdata/kong2kic/7-service-route-upstream-jwt-auth/input.yaml",
				outputFilename: "testdata/kong2kic/7-service-route-upstream-jwt-auth/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route, key auth plugin",
			args: args{
				inputFilename:  "testdata/kong2kic/8-service-route-upstream-key-auth/input.yaml",
				outputFilename: "testdata/kong2kic/8-service-route-upstream-key-auth/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route, mtls auth plugin",
			args: args{
				inputFilename:  "testdata/kong2kic/9-service-route-upstream-mtls-auth/input.yaml",
				outputFilename: "testdata/kong2kic/9-service-route-upstream-mtls-auth/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route, multiple plugin",
			args: args{
				inputFilename:  "testdata/kong2kic/10-mulitple-plugins-same-route/input.yaml",
				outputFilename: "testdata/kong2kic/10-mulitple-plugins-same-route/output-expected.yaml",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputContent, err := GetContentFromFiles([]string{tt.args.inputFilename}, false)
			if err != nil {
				assert.Fail(t, err.Error())
			}

			output, err := KongToKIC(inputContent)
			if (err != nil) != tt.wantErr {
				t.Errorf("KongToKIC() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {

				expected, err := os.ReadFile(tt.args.outputFilename)
				if err != nil {
					assert.Fail(t, err.Error())
				}
				assert.Equal(t, string(expected), string(output))
			}
		})
	}
}
