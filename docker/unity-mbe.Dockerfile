# Unity's MonoBleedingEdge fork (Unity-Technologies/mono), built with Unity's Linux configure flags
# (external/buildscripts/build.pl), plus a C host that embeds libmonobdwgc-2.0.so like a Unity player.
# The stock mono:6.12 base provides the bootstrap compiler for the class libraries and `mcs` for the
# e2e fixtures.
#
#   docker build -f docker/unity-mbe.Dockerfile -t frida-mono/unity-mbe docker   (≈ 30-60 min)

FROM mono:6.12 AS build
ARG MONO_REF=75711b4363fa58f05f953b3f95400d4d61c0ca35
# Buster is archived; its packages live on archive.debian.org now.
RUN printf 'deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n' > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates autoconf automake libtool make cmake g++ python3 gettext perl pkg-config bzip2 xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN git init /src && cd /src \
    && git remote add origin https://github.com/Unity-Technologies/mono.git \
    && git fetch --depth 1 origin "$MONO_REF" && git checkout FETCH_HEAD \
    && git submodule update --init --depth 1 --jobs 8
WORKDIR /src
ENV CFLAGS="-fPIC -Os"
RUN ./autogen.sh --prefix=/opt/unity-mono \
      --with-glib=embedded --disable-nls --with-mcs-docs=no \
      --enable-no-threads-discovery=yes --enable-ignore-dynamic-loading=yes \
      --enable-dont-register-main-static-data=yes --enable-thread-local-alloc=no \
      --enable-unity-define=yes --with-monotouch=no \
      --disable-parallel-mark --enable-minimal=com --enable-verify-defines
RUN make -j"$(nproc)" && make install
# Players load the Boehm runtime under this name.
RUN cp mono/mini/.libs/libmonoboehm-2.0.so /opt/unity-mono/lib/libmonobdwgc-2.0.so
COPY unity-host.c /tmp/
RUN gcc -O2 -o /opt/unity-mono/bin/unity-host /tmp/unity-host.c -ldl \
    && cp /opt/unity-mono/bin/unity-host /opt/unity-mono/bin/unity-host-delayed

FROM mono:6.12
COPY --from=build /opt/unity-mono /opt/unity-mono
# Unity's runtime looks for the class libraries under Unity's profile name, not 4.5.
RUN ln -s 4.5 /opt/unity-mono/lib/mono/net_4_x-linux
