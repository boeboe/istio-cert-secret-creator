# Istio certificate secret creator

This container image creates Istio Service Mesh certificates and exposes them in a Kubernetes [Secret](https://kubernetes.io/docs/concepts/configuration/secret).

In most Istio use cases, when a workload starts, an `istio-agent` component running in `istio-proxy` container creates CSR request for the workload and sends it to Istiod via gRPC API. Istiod signs the CSR request and sends back the signed certificate to `istio-agent`. Envoy proxy (running in the same `istio-proxy` container as `istio-agent`) then requests the certificate from istio-agent via SDS API. The certificate in the Envoy proxy sidecar represents the [workload identity](https://istio.io/latest/docs/concepts/security/#istio-identity) and is used during [mTLS](https://istio.io/latest/docs/concepts/security/#mutual-tls-authentication) establishment and is the cornerstone of Istio's [authentication](https://istio.io/latest/docs/concepts/security/#authentication-policies) and [authorization](https://istio.io/latest/docs/concepts/security/#authorization-policies).

In some cases, however, operational admins want workloads to join the mesh with a valid certificate, without relying on the `istio-proxy` sidecar. Some use cases include:
 - Windows container POD's running on Windows Kubernetes nodes. The `istio-proxy` sidecar currently does not support Windows environments.
 - Concerns about latency introduced by sidecar injection, or other reasons to directly terminate mTLS in the application.

Note that depending on the use case (**sidecar workload => secret mounting workload** vs **secret mounting workload => sidecar workload**), some of the features offered by the `envoy-proxy` sidecar will not be available.

## Build

In case you want to modify the logic and/or build this container from scratch, the following helper `makefile` targets can help you.

```bash
$ make

  help                           This help
  build                          Build the container
  run                            Run container
  shell                          Run shell in container
  stop                           Stop and remove a running container
  publish                        Tag and publish container
  release                        Make a full release
  deploy                         Deploy within the istio-system namespace
  undeploy                       Undeploy from the istio-system namespace
  deploy-test                    Create some test namespaces and serviceaccounts
  undeploy-test                  Delete the test namespaces and serviceaccounts
```

In case you run the container outside kubernetes, you need to bindmount a valid `.kube` directory in order to be able to access a kubernetes API server. Check the `Makefile` for some valid `docker run` examples. Within kubernetes itself, this is handled automatically.

## Deploy

In order to deploy this container, you have to create a deployment with corresponding serviceaccount, clusterrole and clusterrolebinding, as exampled in the [kubernetes](./kubernetes) folder.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cert-secret-creator
  namespace: istio-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-secret-creator
rules:
  - apiGroups:
      - ''
    resources:
      - configmaps
    verbs:
      - get
      - list
  - apiGroups:
      - ''
    resources:
      - namespaces
    verbs:
      - get
      - list
  - apiGroups:
      - ''
    resources:
      - secrets
    verbs:
      - create
      - get
      - list
      - patch
  - apiGroups:
      - ''
    resources:
      - serviceaccounts
    verbs:
      - get
      - list
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-secret-creator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-secret-creator
subjects:
  - kind: ServiceAccount
    name: cert-secret-creator
    namespace: istio-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-secret-creator
  namespace: istio-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cert-secret-creator
  template:
    metadata:
      labels:
        app: cert-secret-creator
    spec:
      containers:
        - image: boeboe/istio-cert-secret-creator:0.1.0
          imagePullPolicy: Always
          name: cert-secret-creator
          resources:
            limits:
              cpu: 250m
              memory: 128Mi
      serviceAccountName: cert-secret-creator
```

## Usage

In order to instrument your service account for certificate secret creation, you have to use labels on the namespace and serviceaccount you want to instrument.

In the following example, the `pem-showcase` namespace will be scanned for target serviceaccounts.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    cert-as-secret.tetrate.io/enabled: 'true'
  name: pem-showcase
---
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    cert-as-secret.tetrate.io/cert-max-ttl: 1w
    cert-as-secret.tetrate.io/cert-secret-name: combined-name
    cert-as-secret.tetrate.io/cert-ttl: 1d
    cert-as-secret.tetrate.io/cert-type: pem
    cert-as-secret.tetrate.io/enabled: 'true'
  name: pem-combined
  namespace: pem-showcase
```

The following is the overview of the available labels:

| Label | Default Value | Explanation | Mandatory |
|-------|---------------|-------------|-----------|
|`cert-as-secret.tetrate.io/cert-max-ttl`| 7d | The not_valid_after field within the certificate | No |
|`cert-as-secret.tetrate.io/cert-pkcs12-password`| istio | The password used for the pkcs12 envelope | No |
|`cert-as-secret.tetrate.io/cert-secret-name`| <serviceaccount_name>-cert-secret | Unique name of your secret | No |
|`cert-as-secret.tetrate.io/cert-ttl`| 1h | The ttl of your certificate, after which it will be rotated | No |
|`cert-as-secret.tetrate.io/cert-type`| pem | The type of your secret, can be `pem` or `pkcs12` | No |
|`cert-as-secret.tetrate.io/enabled`| - | To enable scanning, required both on the namespace and the serviceaccount | Yes |

TTL values can be expressed in second (`5s`), minutes (`10m`), hours (`2h`), days (`1d`), weeks (`4w`) or years (`1y`).

### PEM Certificates

For `cert-as-secret.tetrate.io/cert-type: pem` use cases, the secret contains the following secret data:

```yaml
apiVersion: v1
data:
  cert-chain.pem: <base64 encoded certificate trust chain (all the way to the root certificate, if applicable)>
  cert.pem: <base64 encoded workload public certificate>
  key.pem: <base64 encoded workload private key>
kind: Secret
metadata:
  name: unique-name
  namespace: pem-showcase
type: Opaque
```

### PKCS12 Certificates

For `cert-as-secret.tetrate.io/cert-type: pkcs12` use cases, the secret contains the following data:

```yaml
apiVersion: v1
data:
  cert.p12: <base64 encoded workload pkcs12 envelope, containing the workload public certificate, workload private key and the certificate trust chain (all the way to the root certificate, if applicable)>
kind: Secret
metadata:
  name: unique-name
  namespace: pkcs12-showcase
type: Opaque
```

Note that the pkcs12 envelope requires a password. The default password used is `istio`, but this can be modified by the `cert-as-secret.tetrate.io/cert-pkcs12-password` label.

## Note

There are some inherent security issues by exposing certificates as [Secrets](https://kubernetes.io/docs/concepts/configuration/secret) within kubernetes. Istio avoids these issues by directly injecting certificates in memory (gRPC exchanged), thereby avoiding kubernetes Secrets or on disk storage. This proof of concept is only ment to offer a possible integration scenario for workloads that can not or chose not to leverage the `istio-proxy` sidecar model. Consider the trade-offs that come with this approach carefully.

Note that [Envoy support on Windows](https://blog.envoyproxy.io/general-availability-of-envoy-on-windows-267e4544994a) was announced on May 19 2021, so in the foreseeable future there might be a `istio-proxy` sidecar fully compatible with the Windows container system.

Another thing to consider is the fact that a POD only mounts a secret/configmap once, at startup time. Corresponding changes to the secret will not be picked up by the container without extra measures. Those might include some of the following strategies:
 - File system notifications combined with a config/secret poller as sidecar: [example](https://golangexample.com/sidecar-to-watch-a-config-folder-and-reload-a-process-when-it-changes)
 - A forced restart of the PODs that use the serviceaccount when a certificate is issued/rotated, in a rolling upgrade manner (always making sure at least one POD is reachable, while all get deleted/refreshed over a period of time). This logic can be easily implemented into the existing code base of this POC.

Last but not least, **this is proof of concept code**, so do not use this in production!

## Extra

The content of a standard istiod (citadel) issued certificate looks like this, and we use exacltly the same fields and configuration in this proof of concept for certificate generation.

```bash
$ openssl x509 -in istio-sidecar-cert.pem -text -noout

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                fc:bd:66:97:96:e5:66:7a:bc:81:61:e5:18:d4:1b:94
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: O = Istio, CN = Intermediate CA, L = gcp-tid-windows-cluster
            Validity
                Not Before: Mar 10 14:13:26 2022 GMT
                Not After : Mar 11 14:15:26 2022 GMT
            Subject: 
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    RSA Public-Key: (2048 bit)
                    Modulus:
                        00:a6:88:ea:9b:fa:33:5b:3c:01:0b:60:9c:0e:73:
                        64:8f:ef:37:6f:ce:46:71:8f:41:ed:8a:c1:ac:e3:
                        2b:7a:f1:19:e6:14:83:03:32:22:00:bb:7f:d4:7e:
                        ed:60:95:bf:e9:17:78:91:a6:07:13:57:32:1a:02:
                        2f:ac:75:9d:c9:d6:17:6c:a9:b4:ff:2d:eb:8c:a2:
                        07:d6:48:3a:c9:e0:49:4b:ca:08:08:00:d8:04:13:
                        f6:4a:79:e3:9b:12:17:c5:01:2c:a7:0c:42:42:9a:
                        a9:6d:db:8d:66:4b:28:a4:c1:a0:1e:90:b5:fc:9d:
                        04:c7:9a:d0:e2:9b:6f:7b:50:ed:b4:5d:2d:2f:38:
                        ea:66:bc:89:1e:17:f6:35:c1:43:a1:ea:17:84:df:
                        2d:06:2b:02:b4:e4:1c:32:0b:34:60:98:c4:98:08:
                        d1:22:72:fa:b2:b3:45:71:c7:6e:e4:20:81:49:f4:
                        55:00:c5:90:49:1e:55:3c:95:80:7b:1f:9f:a0:16:
                        f9:92:3f:3e:53:9a:a2:4d:8e:6d:6e:68:84:45:48:
                        35:07:16:23:d1:a4:ed:22:e6:9b:47:1d:d8:de:fa:
                        d8:69:da:16:98:eb:8a:99:e4:68:02:33:eb:f6:fe:
                        bd:ec:61:e8:22:ad:27:46:2b:21:ba:08:42:43:8e:
                        32:e9
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Digital Signature, Key Encipherment
                X509v3 Extended Key Usage: 
                    TLS Web Server Authentication, TLS Web Client Authentication
                X509v3 Basic Constraints: critical
                    CA:FALSE
                X509v3 Authority Key Identifier: 
                    keyid:15:E1:F1:D3:12:D1:D4:C2:AA:26:64:D7:65:AA:6F:BC:0F:A3:01:5E

                X509v3 Subject Alternative Name: critical
                    URI:spiffe://cluster.local/ns/default/sa/default
        Signature Algorithm: sha256WithRSAEncryption
            d2:e3:20:a6:f0:0c:93:b7:ba:79:7f:33:2a:17:53:4e:2b:94:
            a6:91:96:c1:2c:c6:c0:1e:87:7a:31:91:d1:6d:45:43:68:50:
            6e:80:7e:3e:96:9c:7b:1d:fe:d5:2c:b2:3b:67:86:ff:a3:d0:
            91:b5:db:11:18:81:04:7b:8c:eb:05:34:6d:19:d0:9a:5d:21:
            74:23:f3:cf:8c:2e:10:b8:b4:01:45:79:79:24:2a:5d:54:9c:
            be:2e:2a:01:f3:72:12:ac:39:be:ba:27:52:1e:11:c2:4c:6a:
            66:d9:8d:9f:ee:c6:48:a9:dc:12:a7:ba:55:94:5c:eb:0c:33:
            f8:e7:2b:be:9e:d3:21:ad:e6:06:29:34:85:d0:1c:3b:52:b5:
            01:6e:09:8c:2a:f7:72:e5:e4:1f:79:76:63:33:c6:b6:2e:c0:
            1a:05:08:50:d5:e3:16:bf:99:68:64:01:da:3a:19:a5:84:78:
            56:f6:c4:65:b7:39:dc:32:0d:6b:77:80:d4:10:63:03:ce:1c:
            59:1e:51:76:c7:d2:54:d8:77:11:08:ae:c4:5b:eb:9d:d9:bf:
            63:3b:71:60:d8:98:49:7c:29:a3:43:13:56:1a:42:96:b6:75:
            c2:b7:8a:77:ba:3a:38:10:13:0c:5c:17:fa:07:14:db:4e:56:
            19:64:60:fa:0a:90:25:0f:66:ef:a6:48:af:76:3a:1e:54:80:
            8c:3c:81:38:c4:e2:39:7d:90:55:9f:04:f8:49:aa:4d:0e:48:
            c1:55:a9:79:7e:9b:97:52:55:b4:91:13:5d:72:d9:c6:a3:0a:
            11:f7:3f:32:2c:d0:d0:b4:81:58:6c:51:3e:66:db:25:66:6c:
            ca:b6:81:92:37:d3:43:a0:6e:fa:c0:99:49:0e:38:ef:c3:ef:
            0d:04:35:7b:a9:57:51:f9:11:44:b0:ae:d0:33:b0:63:ef:8f:
            d1:12:5f:47:d8:66:e1:13:17:e4:91:c3:8f:26:6c:c2:74:b9:
            30:c1:45:2d:11:21:f8:d2:48:1d:24:c7:6c:58:49:21:73:bb:
            7e:b0:8a:aa:6c:ff:f3:37:91:38:62:cb:0f:df:a6:e2:a7:76:
            30:19:d3:25:5c:2e:67:ce:d7:7b:63:6d:b3:a3:b0:05:3c:b0:
            de:a3:84:7a:0f:42:3d:0c:2d:50:cb:43:01:31:08:38:e8:cf:
            81:6e:ed:f1:ff:fa:27:27:8a:5f:f8:92:f6:6b:88:5c:f7:71:
            49:5c:e8:97:0a:cb:36:c5:b3:3f:e3:55:6c:b2:14:c5:5d:d7:
            54:44:19:0d:09:6a:83:f1:24:7b:3d:01:ca:a8:3e:ac:05:8b:
            07:ed:b1:a0:c9:e1:b4:75
```

Notice the `SPIFFE` based X509v3 Subject Alternative Name, containing the `trustdomain`, `namespace` and `serviceaccount` of the workload. This triplet is the basis for Istio workload identity distribution and enforcement. More info on SPIFFE, aka Secure Production Identity Framework for Everyone, can be found [here](https://spiffe.io).
