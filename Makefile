# secure-git-signer — top-level developer entrypoints.
.PHONY: help test enclave signer eif deploy synth clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

test: ## Run Go tests for the enclave and client
	cd enclave && go test ./...
	cd client  && go test ./...

enclave: ## Build the enclave app binary (static, for the EIF)
	cd enclave && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags="-s -w -buildid=" -o secure-git-signer-enclave .

signer: ## Build the git-enclave-signer client shim for your machine
	cd client && go build -o git-enclave-signer .

eif: ## Build the Nitro Enclave Image File and capture PCR0 (run on AL2023 + nitro-cli)
	./build/build-eif.sh

deploy: ## Deploy the EC2 enclave host with CDK
	cd iac && npm install && npx cdk deploy

synth: ## Synthesize the CloudFormation template without deploying
	cd iac && npm install && npx cdk synth

clean:
	rm -f enclave/secure-git-signer-enclave client/git-enclave-signer build/*.eif pcr0.txt
