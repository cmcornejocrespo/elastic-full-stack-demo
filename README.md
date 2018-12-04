# Elastic full stack demo

## Stack components

Elastic stack based on:
* elasticsearch
* logstash
* kibana
* filebeat
* metricbeat
* packetbeat
* heartbeat
* auditbeat
* reader (demo app)
* todo (demo app)

## Configuration
- elasticsearch.yml [doc](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)

```yaml
cluster.name: "elastic-cluster"
network.host: 0.0.0.0

discovery.zen.minimum_master_nodes: 1

discovery.type: single-node

xpack.monitoring.collection.enabled: true
```

- kibana.yml [doc](https://www.elastic.co/guide/en/kibana/current/index.html)

```yaml
server.name: kibana
server.host: "0"
elasticsearch.url: http://elasticsearch:9200
```

- logstash.yml [doc](https://www.elastic.co/guide/en/logstash/current/index.html)
```yaml
http.host: "0.0.0.0"
path.config: /usr/share/logstash/pipeline
xpack:
  monitoring:
    enabled: true
    elasticsearch.url: http://elasticsearch:9200
```

- filebeat.yml [doc](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)

```yaml
filebeat.autodiscover:
  # List of enabled autodiscover providers
  providers:
    - type: docker
      templates:
        - condition:
            or:
              - equals:
                  docker.container.name: wso2am
              - equals:
                  docker.container.name: cards
              - equals:
                  docker.container.name: global-position
          config:
            - type: log
              paths:
                - /var/lib/docker/containers/${data.docker.container.id}/*.log
              fields_under_root: true
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.kibana:
  host: "kibana:5601"

output.logstash:
  hosts: ["logstash:5555"]

xpack.monitoring:
  enabled: true
  elasticsearch:
    hosts: ["http://elasticsearch:9200"]
```
- metricbeat.yml [doc](https://www.elastic.co/guide/en/beats/metricbeat/current/index.html)
```yaml
output.elasticsearch:
  hosts: ['elasticsearch:9200']

setup.kibana:
  host: "http://kibana:5601"

metricbeat.modules:
- module: docker
  metricsets: ["container", "cpu", "diskio", "healthcheck", "info", "memory", "network"]
  hosts: ["unix:///var/run/docker.sock"]
  period: 10s
- module: kibana
  metricsets:
    - stats
  period: 10s
  hosts: ["http://kibana:5601"]
  xpack.enabled: true

xpack.monitoring:
  enabled: true
```

- packetbeat.yml [doc](https://www.elastic.co/guide/en/beats/packetbeat/current/index.html)

```yaml
packetbeat.interfaces.device: any

packetbeat.flows:
  timeout: 30s
  period: 10s

packetbeat.protocols.dns:
  ports: [53]
  include_authorities: true
  include_additionals: true

packetbeat.protocols.http:
  ports: [80, 5601, 9200, 8080, 8081, 5000, 8002]

packetbeat.protocols.mongodb:
  ports: [27017]

processors:
- add_cloud_metadata:

output.elasticsearch:
  hosts: ['localhost:9200']

setup.kibana:
  host: "http://localhost:5601"

xpack.monitoring.enabled: true
```

- heartbeat.yml [doc](https://www.elastic.co/guide/en/beats/heartbeat/current/index.html)
```yaml
heartbeat.monitors:
- type: http
  schedule: '@every 5s'
  urls:
    - https://elasticsearch:9200
    - http://kibana:5601

- type: icmp
  schedule: '@every 5s'
  hosts:
    - elasticsearch
    - kibana

processors:
- add_cloud_metadata:

output.elasticsearch:
  hosts: ['elasticsearch:9200']

setup.kibana:
  host: "http://kibana:5601"

xpack.monitoring.enabled: true
```

- auditbeat.yml [doc](https://www.elastic.co/guide/en/beats/auditbeat/current/index.html)
```yaml
auditbeat.modules:

- module: auditd
  audit_rules: |
    -w /etc/passwd -p wa -k identity
    -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -k access

- module: file_integrity
  paths:
  - /bin
  - /usr/bin
  - /sbin
  - /usr/sbin
  - /etc

output.elasticsearch:
  hosts: ['elasticsearch:9200']

setup.kibana:
  host: "http://kibana:5601"

xpack.monitoring.enabled: true
```

- apm-server.yml [doc](https://www.elastic.co/guide/en/apm/get-started/current/index.html)
```yaml
apm-server:
  host: apm-server:8200

output:
  elasticsearch:
    hosts: http://elasticsearch:9200
    indices:
      - index: "apm-%{[beat.version]}-sourcemap"
        when.contains:
          processor.event: "sourcemap"

      - index: "apm-%{[beat.version]}-error-%{+yyyy.MM.dd}"
        when.contains:
          processor.event: "error"

      - index: "apm-%{[beat.version]}-transaction-%{+yyyy.MM.dd}"
        when.contains:
          processor.event: "transaction"

      - index: "apm-%{[beat.version]}-span-%{+yyyy.MM.dd}"
        when.contains:
          processor.event: "span"

setup:
  kibana:
    host: "http://kibana:5601"
  dashboards:
    enabled: true
```

# Issues

- max_map_count
if you get this exception (linux-based systems)
```
max virtual memory areas vm.max_map_count [65530] is too low, increase to at least [262144]
```
[Prod setup](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode)
```
sudo sysctl -w vm.max_map_count=262144
```
- Auditbeats requires 3.16+ kernel
[here](https://www.mysterydata.com/how-to-install-or-upgrade-to-kernel-4-16-in-centos-7-cwp7-and-vestacp/) and [here](https://wiki.centos.org/HowTos/Grub2)
 yum --enablerepo=elrepo-kernel install kernel-ml
