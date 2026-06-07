### Usage examples:

Podman with Nexus + Splunk only:
```bash
podman-compose --profile nexus --profile splunk up -d --build
```

Ansible with Elastic + SQL only:
```bash
ansible-playbook deploy/ansible/main.yml \
  -e "nexus_enabled=false splunk_enabled=false elastic_enabled=true sql_enabled=true" \
  -e "elastic_host=https://elastic:9200 sql_host=sql.corp"
```

K8s worker instantiation:
```bash
sed 's/WORKER_NAME/worker_splunk/g; s/WORKER_PORT/9010/g' worker-template.yaml | kubectl apply -f -
```