ifndef GOPATH
$(error GOPATH environment variable is required)
endif

PACKAGE  = httop
DATE    ?= $(shell date +%FT%T%z)
VERSION ?= 0.0.$(shell git describe --tags --always --dirty --match=v*)

GOCMD    = go
GOBUILD  = $(GOCMD) build
GOCLEAN  = $(GOCMD) clean
GOTEST   = $(GOCMD) test
GOGET    = $(GOCMD) get

LDFLAGS  = -s -w -X main.version=$(VERSION)

######################################################################

all: test build

build: $(PACKAGE)

build-linux: .build-container
	docker run --rm -v `pwd`:/go/src/github.com/bradrf/$(PACKAGE) $(PACKAGE)-build \
	  make -C /go/src/github.com/bradrf/$(PACKAGE) $(PACKAGE)_linux

test:
	$(GOTEST) -v ./...

run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./...
	./$(BINARY_NAME)

clean:
	$(GOCLEAN)
	$(RM) $(PACKAGE) $(PACKAGE)_linux

distclean: clean
	git clean -xdf

######################################################################

$(PACKAGE): vendor
	$(GOBUILD) --ldflags '$(LDFLAGS)' -o $@

$(PACKAGE)_%: vendor
	$(GOBUILD) --ldflags '$(LDFLAGS) -linkmode external -extldflags "-static"' -o $@

.build-container: Dockerfile.build
	docker build -f $< -t $(PACKAGE)-build .
	touch $@

vendor: *.go
	dep ensure

######################################################################

.PRECIOUS: .build-container
