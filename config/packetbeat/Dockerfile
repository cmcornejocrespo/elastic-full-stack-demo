ARG ELK_VERSION
ARG ELASTIC_COMPONENT

FROM docker.elastic.co/beats/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY packetbeat.yml /usr/share/packetbeat/packetbeat.yml

USER root
RUN chown root:packetbeat /usr/share/packetbeat/packetbeat.yml
RUN chmod go-w /usr/share/packetbeat/packetbeat.yml
USER packetbeat