FROM ubuntu:24.04 AS base

RUN apt-get update && \
    apt-get install -y wireguard iproute2 iputils-ping gcc-multilib && \
    apt-get install -y netcat-traditional tcpdump vim && \
    mkdir -p /etc/wireguard /etc/nym/default-nym-node/bridges


FROM rust:1.96 AS builder
WORKDIR /usr/src/nym-bridges

RUN mkdir -p crates/nym-bridges/src/ crates/nym-bridges-types/src/ crates/nym-bridge/src crates/bridge-tools/src crates/bridge-cfg/src

COPY Cargo.toml Cargo.toml
COPY crates/nym-bridges-types/Cargo.toml crates/nym-bridges-types/Cargo.toml
COPY crates/nym-bridges/Cargo.toml crates/nym-bridges/Cargo.toml
COPY crates/nym-bridge/Cargo.toml crates/nym-bridge/Cargo.toml
COPY crates/bridge-tools/Cargo.toml crates/bridge-tools/Cargo.toml
COPY crates/bridge-cfg/Cargo.toml crates/bridge-cfg/Cargo.toml

# add dummy target files to build all dependencies 
RUN echo "fn main() {println!(\"if you see this, the udp_echo build broke\")}" > crates/bridge-tools/src/udp_echo.rs
RUN echo "fn main() {println!(\"if you see this, the client build broke\")}" > crates/bridge-tools/src/client.rs
RUN echo "fn main() {println!(\"if you see this, the client_udp build broke\")}" > crates/bridge-tools/src/client_udp.rs
RUN echo "fn main() {println!(\"if you see this, the udp_sender build broke\")}" > crates/bridge-tools/src/udp_sender.rs
RUN echo "fn main() {println!(\"if you see this, the udp_recv build broke\")}" > crates/bridge-tools/src/udp_recv.rs
RUN echo "fn main() {println!(\"if you see this, the bridge runner build broke\")}" > crates/nym-bridge/src/main.rs
RUN echo "fn main() {println!(\"if you see this, the bridge config build broke\")}" > crates/bridge-cfg/src/main.rs
RUN touch crates/nym-bridges/src/lib.rs crates/nym-bridges-types/src/lib.rs

RUN cargo build --workspace --all-targets --release

# remove dummy compiled targets
RUN rm -f target/release/deps/bridge_cfg* 
RUN rm -f target/release/deps/client*
RUN rm -f target/release/deps/client_udp*
RUN rm -f target/release/deps/udp_sender*
RUN rm -f target/release/deps/udp_recv*
RUN rm -f target/release/deps/nym_bridge* 
RUN rm -f target/release/deps/udp_echo*
RUN rm -f target/release/deps/nym_bridges* target/release/libnym_bridges* target/release/deps/libnym_bridges*

# add in actual source now so rebuild starts from here on change
RUN rm -rf crates
COPY crates/ crates/

COPY bridges.template.toml .

RUN cargo build --workspace --all-targets --release

RUN cargo install --path crates/bridge-cfg
RUN cargo install --path crates/bridge-tools
RUN cargo install --path crates/nym-bridge


FROM base AS wg0

COPY test-env/test-config/*.toml /etc/nym/default-nym-node/
COPY test-env/test-config/keys/* /etc/nym/default-nym-node/bridges/
COPY test-env/wg0/*.conf /etc/wireguard/
COPY test-env/wg0/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY --from=builder /usr/local/cargo/bin/* /usr/local/bin/

ENTRYPOINT ["/entrypoint.sh"]

FROM base AS wg1

COPY test-env/test-config/*.toml /etc/nym/default-nym-node/
COPY test-env/test-config/keys/* /etc/nym/default-nym-node/bridges/
COPY test-env/wg1/*.conf /etc/wireguard/
COPY test-env/wg1/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY --from=builder /usr/local/cargo/bin/* /usr/local/bin/

ENTRYPOINT ["/entrypoint.sh"]
