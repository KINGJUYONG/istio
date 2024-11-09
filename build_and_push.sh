#!/bin/bash

HUB="boanlab"
TAG="customca_test"

export HUB=$HUB
export TAG=$TAG

set -e 

make build

HUB=$HUB TAG=$TAG make docker.pilot
HUB=$HUB TAG=$TAG make docker.proxyv2

docker push $HUB/pilot:$TAG 
docker push $HUB/proxyv2:$TAG

yes | istioctl uninstall --purge

# envsubst < ./default_istio.yaml > ./default_istio_temp.yaml

yes | istioctl install -f ./build_and_push.yaml  --log_output_level=debug

# rm ./default_istio_temp.yaml

kubectl get pods -n istio-system 

istioctl dashboard controlz deployment/istiod.istio-system