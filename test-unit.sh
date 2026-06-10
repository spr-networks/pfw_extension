#!/bin/sh
# Run the pfw nftables differential tests in a privileged container.
docker build -f Dockerfile.test -t pfw-test .
docker run --name pfw-test --privileged --rm pfw-test \
    /bin/bash -c "bash /scripts/nft_rules.sh && cd /code && go test -vet=off -v"
