# append a dash to the end, e.g ARCH=arm64-
ARG ARCH=
FROM fluent/fluentd:v1.19.3-debian-${ARCH}2.4

USER root
WORKDIR /home/fluent
ENV PATH=/fluentd/vendor/bundle/ruby/3.4.0/bin:$PATH
ENV GEM_PATH=/fluentd/vendor/bundle/ruby/3.4.0
ENV GEM_HOME=/fluentd/vendor/bundle/ruby/3.4.0
# skip runtime bundler installation
ENV FLUENTD_DISABLE_BUNDLER_INJECTION=1

COPY Gemfile* /fluentd/

RUN buildDeps="sudo make gcc g++ libc-dev libffi-dev libssl-dev" \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends $buildDeps net-tools \
 && bundle config silence_root_warning true \
 && bundle install --gemfile=/fluentd/Gemfile --path=/fluentd/vendor/bundle \
 && SUDO_FORCE_REMOVE=yes apt-get purge -y --auto-remove \
      -o APT::AutoRemove::RecommendsImportant=false \
      $buildDeps '*-dev' \
 && rm -rf /var/lib/apt/lists/* \
 && gem sources --clear-all \
 && rm -rf /tmp/* /var/tmp/* /usr/lib/ruby/gems/*/cache/*.gem

# Default configuration (convox racks replace /fluentd/etc with their ConfigMap)
COPY ./conf/fluent.conf /fluentd/etc/
COPY ./conf/systemd.conf /fluentd/etc/
COPY ./conf/kubernetes.conf /fluentd/etc/
COPY ./conf/prometheus.conf /fluentd/etc/
RUN touch /fluentd/etc/disable.conf

COPY plugins /fluentd/plugins/
COPY entrypoint.sh /fluentd/entrypoint.sh

ENV FLUENTD_OPT=""
ENV FLUENTD_CONF="fluent.conf"
# LD_PRELOAD=/usr/lib/libjemalloc.so.2 is inherited from fluent/fluentd (not
# cleared as fluent/fluentd-kubernetes-daemonset does).

# Overwrite ENTRYPOINT to run fluentd as root for /var/log / /var/lib
ENTRYPOINT ["tini", "--", "/fluentd/entrypoint.sh"]
