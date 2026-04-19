FROM rust:1 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p nullwarden-server

FROM debian:bookworm-slim
RUN groupadd -r nullwarden && useradd -r -g nullwarden nullwarden
WORKDIR /app
COPY --from=builder /app/target/release/nullwarden-server /usr/local/bin/nullwarden-server
RUN chown nullwarden:nullwarden /usr/local/bin/nullwarden-server
EXPOSE 8080
USER nullwarden
CMD ["nullwarden-server"]
