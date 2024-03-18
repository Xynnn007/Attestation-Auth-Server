FROM rust:latest as builder

WORKDIR /tmp
COPY . .

# Build and Install AAS
RUN cargo install --path .


FROM ubuntu:22.04

COPY --from=builder /usr/local/cargo/bin/aas /usr/local/bin/aas
