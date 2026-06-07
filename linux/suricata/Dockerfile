# syntax=docker/dockerfile:1
# suricata: a high performance, open source network analysis and threat detection software.

ARG repo="quay.io/almalinuxorg" \
    base_image="9-minimal" \
    image_hash="e15aca0729657735744d1e65b115aacc8bb6eec507313ced8394eb16fb9f256b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS base

LABEL \
    org.opencontainers.image.name='Suricata' \
    org.opencontainers.image.description='Suricata is a high performance, open source network analysis and threat detection software.' \
    org.opencontainers.image.usage='https://suricata.readthedocs.io/en/suricata-8.0.3/' \
    org.opencontainers.image.url='https://suricata.io/' \
    org.opencontainers.image.licenses='GNU General Public License v2.0' \
    org.opencontainers.image.vendor='The Open Information Security Foundation (OISF)' \
    org.opencontainers.image.schema-version='8.0.3'

# base dependencies for runtime
RUN \
    microdnf install -y yum-utils epel-release; \
    dnf config-manager --set-enabled crb; \
    /usr/bin/crb enable; \
    microdnf update -y; \
    microdnf install -y \
	bzip2 \
	wget \
	cronie \
	elfutils-libelf \
	file \
	findutils \
	hiredis \
	hyperscan \
	iproute \
	jansson \
	lua-libs \
	libbpf \
	libyaml \
	libnfnetlink \
	libnetfilter_queue \
	libnet \
	libcap-ng \
	libevent \
	libmaxminddb \
	libpcap \
	libprelude \
	logrotate \
	lz4 \
	net-tools \
	nss \
	nss-softokn \
	pcre \
	procps-ng \
	python3 \
	python3-yaml \
	python3-pip \
	tcpdump \
	which \
	zlib \
	clamav \
	openscap \
	scap-security-guide \
	clamav-update

FROM base AS build-env

ARG VERSION=8.0.3

RUN \
    microdnf install -y yum-utils epel-release; \
    dnf config-manager --set-enabled crb; \
    /usr/bin/crb enable; \
    microdnf update -y; \
    microdnf install -y \
	autoconf \
	automake \
	bash \
	cargo \
	cbindgen \
	diffutils \
	elfutils-libelf-devel \
	file \
	file-devel \
	gcc \
	gcc-c++ \
	git \
	hiredis-devel \
	jansson-devel \
	jq \
	lua-devel \
	libbpf-devel \
	libtool \
	libyaml-devel \
	libnfnetlink-devel \
	libnetfilter_queue-devel \
	libnet-devel \
	libcap-ng-devel \
	libevent-devel \
	libmaxminddb-devel \
	libpcap-devel \
	libprelude-devel \
	libtool \
	lz4-devel \
	make \
	nspr-devel \
	nss-devel \
	nss-softokn-devel \
	pcre2-devel \
	pcre-devel \
	pkgconfig \
	python3-devel \
	python3-yaml \
	rust \
	which \
	zlib-devel \
	hyperscan-devel \
	npm \
	gnupg

WORKDIR /src/

RUN \
    for server in $(shuf -e hkps://keys.openpgp.org \
                            hkps://keyserver.ubuntu.com \
	    		    hkps://pgp.mit.edu) ; do \
    gpg --batch --keyserver "${server}" --recv-keys b36fdaf2607e10e8ffa89e5e2ba9c98ccdf1e93a && break || : ; \
    done; \
    curl -OL https://www.openinfosecfoundation.org/download/suricata-${VERSION}.tar.gz.sig; \
    curl -OL https://www.openinfosecfoundation.org/download/suricata-${VERSION}.tar.gz; \
    gpg --batch --verify suricata-${VERSION}.tar.gz.sig suricata-${VERSION}.tar.gz; \
    tar zxvf suricata-${VERSION}.tar.gz

WORKDIR /src/suricata-${VERSION}

RUN \
    ./configure \
    --prefix=/usr \
    --disable-shared \
    --disable-gccmarch-native \
    --enable-lua \
    --enable-nfqueue \
    --enable-hiredis \
    --enable-geoip \
    --enable-ebpf; \
    make -j 2; \
    make install install-conf DESTDIR=/fakeroot; \
    rm -rf /fakeroot/var /root/.gnupg

FROM base

RUN \
    find /etc/logrotate.d -type f -not -name suricata -delete; \
    mkdir -p /var/log/suricata /var/run/suricata /var/lib/suricata

COPY --from=build-env /fakeroot /
COPY logrotate /etc/logrotate.d/suricata
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# bin smoke tests
RUN \
    suricata-update update-sources; \
    suricata-update enable-source oisf/trafficid; \
    suricata-update --no-test --no-reload; \
    /usr/bin/suricata -V

RUN \
    groupadd -g 1001 suricata; \
    useradd -u 1001 -g suricata suricata -m; \
    chown -R suricata:suricata /etc/suricata; \
    chown -R suricata:suricata /var/log/suricata; \
    chown -R suricata:suricata /var/lib/suricata; \
    chown -R suricata:suricata /var/run/suricata; \
    cp -a /etc/suricata /etc/suricata.dist; \
    chmod 600 /etc/logrotate.d/suricata

# Run hardening script and collect build security artifacts, SCA/Compliance/CVE/AV
WORKDIR /home/suricata/artifacts

ARG SCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig \
    SCAP_SNAME=STIG \
    BENCHMARK=ssg-almalinux9-ds.xml

COPY ./el9-container-hardening.sh /home/suricata/artifacts/el9-container-hardening.sh

RUN \
	chmod +x ./el9-container-hardening.sh; \
    bash -c "./el9-container-hardening.sh"; \
    wget https://security.almalinux.org/oval/org.almalinux.alsa-9.xml; \
    oscap oval eval --report suricata-alma9-cve-report.html org.almalinux.alsa-9.xml || :; \
    oscap ds sds-validate /usr/share/xml/scap/ssg/content/${BENCHMARK} \ && echo "ok" || echo "exit code = $? not ok"; \
    oscap xccdf eval --profile ${SCAP_PROFILE} --results suricata_alma9-${SCAP_SNAME}-scap-report.xml \
    --report suricata_alma9-${SCAP_SNAME}-scap-report.html /usr/share/xml/scap/ssg/content/${BENCHMARK} || :; \
    freshclam; \
    clamscan -rvi -l clamav_scan.log --exclude-dir="^/sys" / || :; \
    chown -R suricata:suricata /home/suricata; \
    grep -Hrn FOUND clamav_scan.log; \
    microdnf remove -y clamav clamav-update openscap scap-security-guide wget bzip2; \
    dnf config-manager --set-disabled crb; /usr/bin/crb disable; \
    microdnf remove -y epel-release yum-utils

RUN \
    microdnf clean all; \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/* /var/tmp/*; \
    truncate -s 0 /var/log/*log; \
	# create directories for active blocking IPS setup if needed
	#mkdir -p /etc/suricata/data && chown -R suricata:suricata /etc/suricata/data; \
	#mkdir -p /etc/suricata/rules && chown -R suricata:suricata /etc/suricata/rules; \
    chmod +x /usr/local/bin/entrypoint.sh

# ----------------- IDS/IPS assets (rendered at runtime by entrypoint) ------
# The config is a TEMPLATE rendered from env at start time, so ONE image runs
# as IDS or IPS without a rebuild. Risk-tiered rules + threshold.config provide
# the "block known-bad, escalate suspicious, filter noise" model. The toggle
# script flips rule actions per the RULE_ACTION_POLICY at startup.
#
# ethtool is needed to disable NIC offload for the af-packet bridge; envsubst is
# not required (entrypoint renders with sed).
RUN microdnf install -y ethtool iptables-nft || microdnf install -y ethtool iptables || :

# Template + rules + datasets + threshold config baked in as defaults. At
# runtime these are overlaid by any bind-mounts from docker-compose.
COPY --chown=suricata:suricata templates/suricata.yaml.template /etc/suricata/templates/suricata.yaml.template
COPY --chown=suricata:suricata rules/ /var/lib/suricata/rules/
COPY --chown=suricata:suricata files/threshold.config /etc/suricata/threshold.config
COPY --chown=suricata:suricata files/ /etc/suricata/data/
COPY --chmod=755 scripts/toggle_rule_blocking.py /usr/local/bin/toggle_rule_blocking.py

# Keep the template out of the live data dir (it's not a dataset file).
RUN rm -f /etc/suricata/data/threshold.config 2>/dev/null || :
# --------------------------------------------------------------------------
VOLUME /var/log/suricata
VOLUME /var/lib/suricata
VOLUME /etc/suricata
ENTRYPOINT ["entrypoint.sh"]