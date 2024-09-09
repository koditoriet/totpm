ARG FEDORA_RELEASE=40
FROM fedora:${FEDORA_RELEASE}
VOLUME /build
RUN dnf -y install jq cargo fedpkg
RUN mkdir -p /run/containers/storage /var/lib/containers/storage
COPY ./storage.conf /etc/containers/storage.conf
WORKDIR /build
