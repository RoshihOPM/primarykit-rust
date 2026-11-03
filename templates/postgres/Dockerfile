FROM rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /src/target/release/{{project_name}} /app/server
USER 65532:65532
EXPOSE 8000
CMD ["/app/server"]
