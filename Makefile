.PHONY: build test

build:
	go build -buildvcs=false -trimpath -o build/bin/lfish-capture ./cmd/lfish-capture
	chmod 700 build/bin/lfish-capture
	go build -buildvcs=false -trimpath -tags production,webkit2_41 -o build/bin/lfish .

test:
	go test -buildvcs=false -tags production,webkit2_41 ./...
