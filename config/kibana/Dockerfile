ARG ELK_VERSION
ARG ELASTIC_COMPONENT

# https://github.com/elastic/kibana-docker
FROM docker.elastic.co/${ELASTIC_COMPONENT}/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY kibana.yml /usr/share/kibana/kibana.yml
# Add your kibana plugins setup here
# Example: RUN kibana-plugin install <name|url>
