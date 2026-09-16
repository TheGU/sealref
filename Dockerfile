# A static sealref binary in an image that contains nothing else.
#
# The result is meant to be consumed with COPY --from, so an application image gains sealref
# without gaining a package manager, a shell, or a CA bundle it did not ask for. The rustls root
# certificates are compiled into the binary, which is what lets the Vault provider work from a
# scratch image.

FROM rust:1.98-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=build /src/target/x86_64-unknown-linux-musl/release/sealref /sealref

ENTRYPOINT ["/sealref"]
