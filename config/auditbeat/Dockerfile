ARG ELK_VERSION
ARG ELASTIC_COMPONENT

FROM docker.elastic.co/beats/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY auditbeat.yml /usr/share/auditbeat/auditbeat.yml