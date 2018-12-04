ARG ELK_VERSION
ARG ELASTIC_COMPONENT

# https://github.com/elastic/beats-docker
FROM docker.elastic.co/beats/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY filebeat.yml /usr/share/filebeat/filebeat.yml
USER root
RUN chown root:filebeat /usr/share/filebeat/filebeat.yml
RUN chmod go-w /usr/share/filebeat/filebeat.yml
USER filebeat