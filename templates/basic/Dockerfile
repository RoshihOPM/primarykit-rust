FROM rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /src/target/release/{{project_name}} /app/server
USER 65532:65532
EXPOSE 8000
CMD ["/app/server"]
