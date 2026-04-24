FROM rust:1.81.0-bookworm@sha256:27b6e9bd919166bac1fb9211e9e52449d5fb725a70122e2280b3f235eef01f2f AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p nullwarden-server

FROM debian:bookworm-slim@sha256:a629e796d77a7b2ff82186ed15d01a493801c020eed5ce6adaa2704356f15a1c
RUN groupadd -r nullwarden && useradd -r -g nullwarden nullwarden
WORKDIR /app
COPY --from=builder /app/target/release/nullwarden-server /usr/local/bin/nullwarden-server
RUN chown nullwarden:nullwarden /usr/local/bin/nullwarden-server
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/nullwarden-server", "--help"]
EXPOSE 8080
USER nullwarden
CMD ["nullwarden-server"]
