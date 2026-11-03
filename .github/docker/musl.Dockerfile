# Static musl build environment. The upstream image ships a current Rust toolchain and a static
# zlib, we only need to add a static libunwind for py-spy's `unwind` feature (see remoteprocess's
# build.rs, which expects it in $TARGET_HOME/lib).
FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl

RUN export CC=$TARGET_CC && \
    export C_INCLUDE_PATH=$TARGET_C_INCLUDE_PATH && \
    export CFLAGS="-fPIE" && \
    export LDFLAGS="-fPIE" && \
    VERS=1.8.3 && \
    CHECKSUM=be30d910e67f58d82e753231f1357f326a1a088acf126b21ff77e60aab19b90b && \
    cd /tmp && \
    curl -sqLO https://github.com/libunwind/libunwind/releases/download/v$VERS/libunwind-$VERS.tar.gz && \
    echo "$CHECKSUM libunwind-$VERS.tar.gz" | sha256sum -c && \
    tar xzf libunwind-$VERS.tar.gz && cd libunwind-$VERS && \
    ./configure --prefix=$TARGET_HOME --host=$RUST_MUSL_CROSS_TARGET \
        --enable-ptrace --enable-shared=no \
        --disable-minidebuginfo --disable-zlibdebuginfo --disable-tests --disable-documentation && \
    make -j$(nproc) && make install && \
    cd /tmp && rm -rf libunwind-$VERS libunwind-$VERS.tar.gz
