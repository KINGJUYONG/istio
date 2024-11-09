#!/bin/bash

HUB="boanlab"
BASE_TAG="customca_test"

# Get the current highest number
get_next_number() {
    local highest=0
    
    # Check existing docker images for the pattern
    for tag in $(docker images "$HUB/pilot" --format "{{.Tag}}" | grep "^${BASE_TAG}[0-9]*$"); do
        num=${tag#$BASE_TAG}
        if [[ $num =~ ^[0-9]+$ ]] && ((num > highest)); then
            highest=$num
        fi
    done
    
    # Return next number
    echo $((highest + 1))
}

# Get the next number and set the TAG
next_num=$(get_next_number)
TAG="${BASE_TAG}${next_num}"

export HUB=$HUB
export TAG=$TAG

echo "Building with TAG: $TAG"

set -e 

make build

HUB=$HUB TAG=$TAG make docker.pilot
HUB=$HUB TAG=$TAG make docker.proxyv2

docker push $HUB/pilot:$TAG 
docker push $HUB/proxyv2:$TAG

yes | istioctl uninstall --purge

envsubst < ./build_and_push.yaml > ./build_and_push_temp.yaml

yes | istioctl install -f ./build_and_push_temp.yaml  --log_output_level=debug

rm ./build_and_push_temp.yaml

kubectl get pods -n istio-system

# istioctl dashboard controlz deployment/istiod.istio-system