On build host:

./harness.sh build
docker save tee-harness -o img
rsync -vv --progress img blind-audit:img



On AWS machine:

docker load -i img
nitro-cli-config -d /home/ubuntu/aws-nitro-enclaves-cli/ -i -m 2048 -t 2
nitro-cli build-enclave --docker-uri tee-harness:latest --output-file tee-harness.eif
nitro-cli run-enclave --eif-path tee-harness.eif --cpu-count 2 --memory 2000 --debug-mode
nitro-cli terminate-enclave --all

