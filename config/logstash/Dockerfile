ARG ELK_VERSION
ARG ELASTIC_COMPONENT

# https://github.com/elastic/logstash-docker
FROM docker.elastic.co/${ELASTIC_COMPONENT}/${ELASTIC_COMPONENT}:${ELK_VERSION}
COPY logstash.yml /usr/share/logstash/logstash.yml
COPY logstash.conf /usr/share/logstash/pipeline/logstash.conf

# Add your logstash plugins setup here
# Example: RUN logstash-plugin install logstash-filter-json
