ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src
COPY src src
COPY migrations migrations
COPY Cargo.lock Cargo.lock
COPY Cargo.toml Cargo.toml
ENV FFMPEG_DIR=/app/ffmpeg
RUN apt update && \
    apt install -y \
    build-essential \
    libx264-dev \
    libwebp-dev \
    libvpx-dev \
    nasm \
    libclang-dev && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --single-branch --branch release/7.1 https://github.com/ffmpeg/FFmpeg.git && \
    cd FFmpeg && \
    ./configure \
    --prefix=${FFMPEG_DIR} \
    --disable-programs \
    --disable-doc \
    --disable-network \
    --enable-gpl \
    --enable-libx264 \
    --enable-libwebp \
    --enable-libvpx \
    --disable-static \
    --disable-postproc \
    --enable-shared && \
    make -j$(nproc) install
RUN rm Cargo.lock
# RUN cargo tree -i half | cat
RUN mkdir -p ~/.cargo && \
    echo '[net]' > ~/.cargo/config.toml && \
    echo 'git-fetch-with-cli = true' >> ~/.cargo/config.toml
RUN cargo install --path . --root /app/build --features "blossom,ranges"

FROM node:bookworm AS ui_builder
WORKDIR /app/src
COPY ui_src .
RUN yarn && yarn build

FROM debian:bookworm-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y libx264-164 libwebp7 libvpx7 ca-certificates libxcb1 libxcb-shm0 && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r appgroup && useradd --no-log-init -r -g appgroup appuser

COPY --from=build /app/build .
COPY --from=ui_builder /app/src/dist ui
COPY --from=build /app/ffmpeg/lib/libavcodec.so.* /lib/
COPY --from=build /app/ffmpeg/lib/libavdevice.so.* /lib/
COPY --from=build /app/ffmpeg/lib/libavfilter.so.* /lib/
COPY --from=build /app/ffmpeg/lib/libavformat.so.* /lib/
COPY --from=build /app/ffmpeg/lib/libavutil.so.* /lib/
COPY --from=build /app/ffmpeg/lib/libswresample.so.* /lib/
COPY --from=build /app/ffmpeg/lib/libswscale.so.* /lib/

# Update the linker cache
RUN ldconfig

RUN chown -R appuser:appgroup /app
RUN chown -R appuser:appgroup /lib

RUN ls -l /app && ls -l /app/bin

USER appuser

# === DIAGNOSTICS START ===
RUN echo "--- Diagnostics --- Running as: $(whoami)"
RUN echo "--- Finding libwebp/mux files ---"
# Check for both libwebp and libwebpmux in system and /lib locations
RUN ls -l /usr/lib/*-linux-gnu/libwebp* /usr/lib/*-linux-gnu/libwebpmux* /lib/libwebp* /lib/libwebpmux* || echo "Webp/mux libs not found in expected locations"
RUN echo "--- Checking ldconfig cache for webp/mux ---"
# Grep cache for both webp and webpmux
RUN ldconfig -p | grep -E 'webp|webpmux' || echo "Webp/mux libs not found in ldconfig cache"
RUN echo "--- Checking dependencies for route96 ---"
RUN ldd /app/bin/route96 || echo "ldd command failed"
RUN echo "--- Diagnostics END ---"

RUN LD_LIBRARY_PATH=/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH ./bin/route96 --version
ENTRYPOINT ["/bin/sh", "-c", "LD_LIBRARY_PATH=/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH /app/bin/route96 $*"]