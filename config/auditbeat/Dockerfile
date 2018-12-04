ARG ELK_VERSION
ARG ELASTIC_COMPONENT

# https://github.com/elastic/beats-docker
FROM docker.elastic.co/beats/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY auditbeat.yml /usr/share/auditbeat/auditbeat.yml