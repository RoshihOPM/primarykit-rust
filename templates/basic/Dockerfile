FROM rust:1-alpine@sha256:98e4492621c23872a502a7171b7d2b105fdc114276856f71051f38bf94ee26aa AS builder
RUN apk add --no-cache build-base pkgconf

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
WORKDIR /app
COPY --from=builder /src/target/release/{{project_name}} /app/server
USER 65532:65532
EXPOSE 8000
CMD ["/app/server"]
