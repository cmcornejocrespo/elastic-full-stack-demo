ARG ELK_VERSION
ARG ELASTIC_COMPONENT

FROM docker.elastic.co/beats/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY metricbeat.yml /usr/share/metricbeat/metricbeat.yml
USER root
RUN chown root:metricbeat /usr/share/metricbeat/metricbeat.yml
RUN chmod go-w /usr/share/metricbeat/metricbeat.yml
USER metricbeat