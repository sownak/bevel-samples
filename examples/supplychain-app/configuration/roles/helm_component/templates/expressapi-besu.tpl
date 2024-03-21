apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: {{ name }}-expressapi
  namespace: {{ component_ns }}
  annotations:
    fluxcd.io/automated: "false"
spec:
  releaseName: {{ name }}{{ network.type }}-expressapi
  interval: 1m
  chart:
    spec:
      chart: {{ component_gitops.chart_source }}/expressapp-besu
      sourceRef:
        kind: GitRepository
        name: flux-{{ network.env.type }}-app
        namespace: flux-{{ network.env.type }}-app
  values:
    nodeName: {{ name }}-expressapi
    metadata:
      namespace: {{ component_ns }}
    replicaCount: 1
    vault:
      address: {{ organization_data.vault.url }}
      secretprefix: {{ organization_data.vault.secret_path | default('secretsv2') }}/data/{{ network.env.type }}{{ organization_data.name | lower }}/smartContracts
      node_address_secret: {{ organization_data.vault.secret_path | default('secretsv2') }}/data/{{ network.env.type }}{{ organization_data.name | lower }}/besu-node-{{ name }}-keys
      serviceaccountname: vault-auth
      contractName: {{ contract_name_value }}
      role: vault-role
      authpath: {{ network.env.type }}{{ organization_data.name | lower }}
    images:
      alpineutils: {{ network.docker.url }}/alpine-utils:1.0
    expressapp:
      serviceType: ClusterIP
      image: ghcr.io/hyperledger/bevel-supplychain-besu:latest
      pullPolicy: IfNotPresent
      pullSecrets: regcred
      nodePorts:
        port: {{ peer_express_api_port }}
        targetPort: {{ peer_express_api_targetport }}
        name: tcp
      env:
        geth_address: {{ geth_address }}
        node_subject: {{ peer_data.subject }}
        node_organization: {{ organization_data.unit }}
        node_organization_unit: {{ organization_data.unit | lower }}
        protocol: {{ network.config.consensus }}
    proxy:
      provider: {{ network.env.proxy }}
      name: {{ organization_data.name }}
      external_url_suffix: {{ organization_data.external_url_suffix }}
      peer_name: {{ name }}
