# The image act runs the Linux CI jobs in. GitHub's ubuntu-latest runner has rustup with a stable
# toolchain installed, and catthehacker's act image does not, so this adds it.
FROM catthehacker/ubuntu:act-latest

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
          --component clippy,rustfmt \
 && rustc --version && cargo --version
