ARG ELK_VERSION
ARG ELASTIC_COMPONENT

FROM docker.elastic.co/apm/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY apm-server.yml /usr/share/apm-server/apm-server.yml
USER root
RUN chown root:apm-server /usr/share/apm-server/apm-server.yml
RUN chmod go-w /usr/share/apm-server/apm-server.yml
USER apm-server