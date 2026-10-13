# Unity's legacy Mono 2.6 fork (Unity-Technologies/mono, branch unity-2018.4 — the last Unity with
# the ".NET 3.5" scripting runtime), built with Unity's Linux flags
# (external/buildscripts/build_runtime_linux.pl). Unity builds its class libraries in a separate
# pipeline; this image pairs the runtime with Debian squeeze's stock Mono 2.6.7 class libraries,
# whose corlib version (82) matches. Debian squeeze also provides the toolchain of that era and
# `gmcs` for the e2e fixtures.
#
#   node scripts/build-unity-images.mjs legacy

FROM debian/eol:squeeze AS build
ARG MONO_REF=e20cf158facacfe732f4b53c0501e7263e114efd
RUN apt-get update && apt-get install -y --force-yes --no-install-recommends \
      build-essential autoconf automake libtool bison pkg-config gettext ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
# Squeeze's git and TLS stack are too old for GitHub; scripts/build-unity-images.mjs packs the tree on the host.
COPY legacy-src.tar.gz /tmp/
RUN mkdir /src && tar -C /src -xzf /tmp/legacy-src.tar.gz
WORKDIR /src
ENV CFLAGS="-DLINUX=1 -fPIC -Os" CPPFLAGS="-DLINUX=1 -fPIC -Os" CXXFLAGS="-DLINUX=1 -fPIC -Os"
RUN cd eglib && autoreconf -i && cd .. && autoreconf -i \
    && ./configure --prefix=/opt/unity-mono --disable-mcs-build --with-glib=embedded --disable-nls --disable-parallel-mark \
    && make -j"$(nproc)" && make install
RUN cp mono/mini/.libs/libmono.so.0 /opt/unity-mono/lib/libmono.so
COPY unity-host.c /tmp/
RUN gcc -O2 -o /opt/unity-mono/bin/unity-host /tmp/unity-host.c -ldl \
    && cp /opt/unity-mono/bin/unity-host /opt/unity-mono/bin/unity-host-delayed

FROM debian/eol:squeeze
RUN apt-get update && apt-get install -y --force-yes --no-install-recommends mono-gmcs libmono-system2.0-cil \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/unity-mono /opt/unity-mono
# The runtime looks for class libraries under <prefix>/lib/mono/2.0: use the system ones.
RUN rm -rf /opt/unity-mono/lib/mono && ln -s /usr/lib/mono /opt/unity-mono/lib/mono \
    && mkdir -p /opt/unity-mono/etc/mono && cp /etc/mono/config /opt/unity-mono/etc/mono/config
