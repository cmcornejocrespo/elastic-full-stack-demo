ARG ELK_VERSION
ARG ELASTIC_COMPONENT

# https://github.com/elastic/elasticsearch-docker
FROM docker.elastic.co/${ELASTIC_COMPONENT}/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY elasticsearch.yml /usr/share/elasticsearch/elasticsearch.yml


# Add your elasticsearch plugins setup here
# Example: RUN elasticsearch-plugin install analysis-icu
