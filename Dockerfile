FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && printf 'fn main() {}\n' > src/main.rs && cargo build --release --locked
COPY src ./src
COPY web ./web
# The dependency warm-up layer contains a placeholder main.rs. Touch the real
# entry point so Cargo never reuses that no-op binary when source mtimes match.
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/yamreg /usr/local/bin/yamreg
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["yamreg"]
CMD ["--root", "/data", "serve", "--bind", "0.0.0.0:8080"]
