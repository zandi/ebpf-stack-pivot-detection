FROM rust:1.68 as builder
WORKDIR /stack_pivot_poc
COPY . .
RUN apt-get update && apt-get install -y libelf-dev clang && rm -rf /var/lib/apt/lists/* && rustup component add rustfmt
RUN cargo install --path .

# TODO: try doing this with alpine for a smaller image
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y libelf1 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /stack_pivot_poc/target/release/stack_pivot_poc /stack_pivot_poc
CMD ["/stack_pivot_poc"]
