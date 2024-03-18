# Attestation Auth Server

This is a experimental project aiming to binding remote attestation to authentication and authorization.

## Run

```shell
# Generate certs and keys
./generate_certs.sh

# Launch AAS + CoCo-AS
docker-compose up -d

# Register a new test id
curl -k -X POST https://127.0.0.1:8080/register \
    -H "Content-Type: application/json" \
    -d '{"id":"spiffe://test", "policy_ids":["default"], "allowed_resources": ["repo/type/tag", "/repo/type/tag"]}'

AAS_DIR=$(pwd)
```

Then, we use a client tool (s.t. CDH to access the AAS)

Firstly, launch AA
```shell
git clone https://github.com/Xynnn007/guest-components.git
cd guest-components && git checkout cai
pushd attestation-agent
make ttrpc=true
popd

RUST_LOG=debug target/x86_64-unknown-linux-gnu/release/attestation-agent 
```

Then, in the same workspace of `guest-components`, launch CDH
```shell
pushd confidential-data-hub
make RESOURCE_PROVIDER=kbs KMS_PROVIDER=none
popd

RUST_LOG=debug target/x86_64-unknown-linux-gnu/release/confidential-data-hub \
    -c ${AAS_DIR}/docker-compose/guest-components/cdh-config.toml
```