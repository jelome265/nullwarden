FROM rust:1.81.0-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p nullwarden-server

FROM debian:bookworm-slim@sha256:a629e796d77a7b2ff82186ed15d01a493801c020eed5ce6adaa2704356f15a1c
RUN groupadd -r nullwarden && useradd -r -g nullwarden nullwarden
WORKDIR /app
COPY --from=builder /app/target/release/nullwarden-server /usr/local/bin/nullwarden-server
RUN chown nullwarden:nullwarden /usr/local/bin/nullwarden-server
EXPOSE 8080
USER nullwarden
CMD ["nullwarden-server"]
