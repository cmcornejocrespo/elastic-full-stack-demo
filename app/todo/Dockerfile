ARG APM_AGENT_VERSION
FROM java:8-jre-alpine

ENV APM_AGENT_URL=https://search.maven.org/remotecontent?filepath=co/elastic/apm/elastic-apm-agent/1.1.0/elastic-apm-agent-1.1.0.jar

RUN apk add --update \
    curl \
    && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/elastic-apm-agent && \
    cd /opt/elastic-apm-agent && \
    curl -O ${APM_AGENT_URL}

VOLUME /tmp
ADD app.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-javaagent:/opt/elastic-apm-agent/elastic-apm-agent-1.1.0.jar","-jar","/app.jar"]