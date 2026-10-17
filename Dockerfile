# Bootstrap image has the complete architecture index. The repository toolchain
# selects the current compiler independently of Docker tag publication timing.
FROM rust:1.99.0-trixie@sha256:81015672d6939b0265f09adf96d5de125482bb1330106076956b0518e74edc90 AS build
WORKDIR /build
ARG TARGETARCH
COPY rust-toolchain.toml ./
RUN test "$(dpkg --print-architecture)" = "$TARGETARCH" && rustup show active-toolchain && rustc --version
ARG NDS_SOURCE_COMMIT
ENV NDS_SOURCE_COMMIT=${NDS_SOURCE_COMMIT}
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY migrations ./migrations
RUN test -n "$NDS_SOURCE_COMMIT" && cargo build --locked --release --jobs 4

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 nds && useradd --uid 10001 --gid 10001 --no-create-home nds
COPY --from=build /build/target/release/nddev-device-sync-server /usr/local/bin/nddev-device-sync-server
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/nddev-device-sync-server"]
CMD ["serve"]
