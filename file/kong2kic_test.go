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
				inputFilename:  "testdata/kong2kic/1/input.yaml",
				outputFilename: "testdata/kong2kic/1/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream",
			args: args{
				inputFilename:  "testdata/kong2kic/2/input.yaml",
				outputFilename: "testdata/kong2kic/2/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream and route",
			args: args{
				inputFilename:  "testdata/kong2kic/3/input.yaml",
				outputFilename: "testdata/kong2kic/3/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route and consumer",
			args: args{
				inputFilename:  "testdata/kong2kic/4/input.yaml",
				outputFilename: "testdata/kong2kic/4/output-expected.yaml",
			},
			wantErr: false,
		},
		{
			name: "convert one service with upstream, route-plugins, consumer",
			args: args{
				inputFilename:  "testdata/kong2kic/5/input.yaml",
				outputFilename: "testdata/kong2kic/5/output-expected.yaml",
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
