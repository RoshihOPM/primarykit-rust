FROM rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/base-nossl-debian13:nonroot
WORKDIR /app
COPY --from=builder /src/target/release/{{project_name}} /app/server
USER 65532:65532
EXPOSE 8000
CMD ["/app/server"]
