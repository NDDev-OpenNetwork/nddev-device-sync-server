FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
WORKDIR /build
ARG NDS_SOURCE_COMMIT
ENV NDS_SOURCE_COMMIT=${NDS_SOURCE_COMMIT}
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY src ./src
COPY migrations ./migrations
RUN test -n "$NDS_SOURCE_COMMIT" && cargo build --locked --release

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 nds && useradd --uid 10001 --gid 10001 --no-create-home nds
COPY --from=build /build/target/release/nddev-device-sync-server /usr/local/bin/nddev-device-sync-server
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/nddev-device-sync-server"]
CMD ["serve"]
