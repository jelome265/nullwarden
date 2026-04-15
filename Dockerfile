FROM rust:1 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p nullwarden-server

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/nullwarden-server /usr/local/bin/nullwarden-server
EXPOSE 8080
CMD ["nullwarden-server"]
