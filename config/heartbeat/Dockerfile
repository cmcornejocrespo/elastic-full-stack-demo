ARG ELK_VERSION
ARG ELASTIC_COMPONENT

# https://github.com/elastic/beats-docker
FROM docker.elastic.co/beats/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY heartbeat.yml /usr/share/heartbeat/heartbeat.yml

USER root
RUN chown root:heartbeat /usr/share/heartbeat/heartbeat.yml
RUN chmod go-w /usr/share/heartbeat/heartbeat.yml
USER heartbeat