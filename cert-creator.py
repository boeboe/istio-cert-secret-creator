#!/usr/bin/env python3

import base64
import datetime
import json
import os
import sys
import yaml

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, BestAvailableEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates, serialize_key_and_certificates
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import ExtendedKeyUsageOID
from kubernetes import client, config
from time import sleep

POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', 10))

# Labels
ENABLE_LABEL="cert-as-secret.tetrate.io/enabled"
CERT_MAX_TTL_LABEL="cert-as-secret.tetrate.io/cert-max-ttl"
CERT_TTL_LABEL="cert-as-secret.tetrate.io/cert-ttl"
CERT_TYPE_LABEL="cert-as-secret.tetrate.io/cert-type"
CERT_PKCS12_PASSWORD_LABEL="cert-as-secret.tetrate.io/cert-pkcs12-password"
CERT_SECRET_NAME_LABEL="cert-as-secret.tetrate.io/cert-secret-name"

# Default values
CERT_MAX_TTL="7d"
CERT_TTL="1h"
CERT_TYPE="pem"
CERT_PKCS12_PASSWORD="istio"
CERT_SECRET_NAME="-cert-secret"


class IstioCACert:
  def __init__(self, istio_ca_secret, trust_domain):
    self.ca_cert = base64.b64decode(istio_ca_secret.data["ca-cert.pem"]).decode()
    self.ca_key = base64.b64decode(istio_ca_secret.data["ca-key.pem"]).decode()
    self.cert_chain = base64.b64decode(istio_ca_secret.data["cert-chain.pem"]).decode()
    self.root_cert = base64.b64decode(istio_ca_secret.data["root-cert.pem"]).decode()
    self.trust_domain = trust_domain
  
  def __str__(self):
    return json.dumps(self.__dict__, indent=2, separators=(',', ': '))

  def get_ca_subject(self):
    cert_info = x509.load_pem_x509_certificate(self.ca_cert.encode(), default_backend())
    return cert_info.subject


class IstioWorkloadCert:
  def __init__(self, istio_ca_cert, labeled_service_account):
    if not isinstance(istio_ca_cert, IstioCACert):
      raise TypeError('Invalid type: istio_ca_cert must be a IstioCACert, not %r' % type(istio_ca_cert))
    if not isinstance(labeled_service_account, LabeledServiceAccount):
      raise TypeError('Invalid type: labeled_service_account must be a LabeledServiceAccount, not %r' % type(labeled_service_account))

    spiffe_uri = f"spiffe://{istio_ca_cert.trust_domain}/ns/{labeled_service_account.namespace}/sa/{labeled_service_account.name}"
    self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(x509.Name([]))
    cert_builder = cert_builder.issuer_name(istio_ca_cert.get_ca_subject())
    cert_builder = cert_builder.public_key(self.private_key.public_key())
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(seconds=labeled_service_account.cert_max_ttl))
    cert_builder = cert_builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False, key_agreement=False,
      key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    cert_builder = cert_builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    cert_builder = cert_builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(load_pem_private_key(istio_ca_cert.ca_key.encode(), password=None).public_key()), critical=False)
    cert_builder = cert_builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]), critical=True)
    self.public_cert = cert_builder.sign(load_pem_private_key(istio_ca_cert.ca_key.encode(), password=None), hashes.SHA256(), default_backend())
    self.cert_chain = istio_ca_cert.cert_chain

  def __str__(self):
    return json.dumps(self.__dict__, indent=2, separators=(',', ': '))

  def get_pem_data(self):
    return (
      self.private_key.private_bytes(serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode(),
      self.public_cert.public_bytes(serialization.Encoding.PEM).decode(),
      self.cert_chain
    )

  def get_pkcs12_data(self, name, password):
    cert_in_chain = ""
    cert_chain_list = []
    for line in self.cert_chain.split('\n'):
      cert_in_chain += line + "\n"
      if '-----END CERTIFICATE-----' in line:
        cert_chain_list.append(load_pem_x509_certificate(cert_in_chain.encode(), backend=default_backend()))
        cert_in_chain = ""
    return serialize_key_and_certificates(
      name=f"{name}".encode(), key=self.private_key, cert=self.public_cert, cas=cert_chain_list, encryption_algorithm=BestAvailableEncryption(password.encode())
    )


class LabeledServiceAccount:
  def __init__(self, namespace, name, cert_max_ttl, cert_ttl, cert_type, cert_pkcs12_password, cert_secret_name):
    self.namespace = namespace
    self.name = name
    self.cert_max_ttl = self.parse_cert_ttl(cert_max_ttl)
    self.cert_ttl = self.parse_cert_ttl(cert_ttl)
    self.cert_type = self.parse_cert_type(cert_type)
    self.cert_pkcs12_password = cert_pkcs12_password
    self.cert_secret_name = self.parse_cert_secret_name(cert_secret_name)

  def __str__(self):
    return json.dumps(self.__dict__, indent=2, separators=(',', ': '))

  def parse_cert_ttl(self, ttl):
    if ttl.endswith('s'): return int(ttl[:-1])
    elif ttl.endswith('m'): return int(ttl[:-1]) * 60
    elif ttl.endswith('h'): return int(ttl[:-1]) * 60 * 60
    elif ttl.endswith('d'): return int(ttl[:-1]) * 60 * 60 * 24
    elif ttl.endswith('w'): return int(ttl[:-1]) * 60 * 60 * 24 * 7
    elif ttl.endswith('y'): return int(ttl[:-1]) * 60 * 60 * 24 * 365
    return -1

  def parse_cert_type(self, cert_type):
    return "pkcs12" if cert_type.lower() == "pkcs12" else "pem"

  def parse_cert_secret_name(self, cert_secret_name):
    return self.name + CERT_SECRET_NAME if cert_secret_name == CERT_SECRET_NAME else cert_secret_name


def get_istio_ca_secret():
  if K8S.list_namespaced_secret("istio-system", field_selector="metadata.name=istio-ca-secret").items:
    return K8S.read_namespaced_secret("istio-ca-secret", "istio-system")
  elif K8S.list_namespaced_secret("istio-system", field_selector="metadata.name=cacerts").items:
    return K8S.read_namespaced_secret("cacerts", "istio-system")
  else:
    sys.exit('Failed to find "istio-ca-secret" or "cacerts" in "istio-system" namespace')


def get_trust_domain():
  istio_configmap = K8S.read_namespaced_config_map("istio", "istio-system")
  try:
    return yaml.safe_load(istio_configmap.data["mesh"])["trustDomain"]
  except yaml.YAMLError as exc:
    sys.exit(f"Failed to parse istio mesh config in istio configmap\n{exc}")


def get_namespaces():
  namespaces = []
  for namespace in K8S.list_namespace(label_selector=f"{ENABLE_LABEL}=true").items:
    namespaces.append(namespace.metadata.name)
  return namespaces


def get_serviceaccounts(*, namespace):
  serviceaccounts_labeled = []
  for sa in K8S.list_namespaced_service_account(namespace, label_selector=f"{ENABLE_LABEL}=true").items:
    labels = sa.metadata.labels
    workload_cert_max_ttl = labels[CERT_MAX_TTL_LABEL] if CERT_MAX_TTL_LABEL in labels else CERT_MAX_TTL
    workload_cert_pkcs12_password = labels[CERT_PKCS12_PASSWORD_LABEL] if CERT_PKCS12_PASSWORD_LABEL in labels else CERT_PKCS12_PASSWORD
    workload_cert_secret_name = labels[CERT_SECRET_NAME_LABEL] if CERT_SECRET_NAME_LABEL in labels else CERT_SECRET_NAME
    workload_cert_ttl = labels[CERT_TTL_LABEL] if CERT_TTL_LABEL in labels else CERT_TTL
    workload_cert_type = labels[CERT_TYPE_LABEL] if CERT_TYPE_LABEL in labels else CERT_TYPE
    
    sa_labeled = LabeledServiceAccount(
      cert_max_ttl=workload_cert_max_ttl,
      cert_pkcs12_password=workload_cert_pkcs12_password,
      cert_secret_name=workload_cert_secret_name,
      cert_ttl=workload_cert_ttl,
      cert_type=workload_cert_type,
      name=sa.metadata.name,
      namespace=sa.metadata.namespace
    )
    serviceaccounts_labeled.append(sa_labeled)
  return serviceaccounts_labeled


def check_refresh_certificate(*, istio_ca_cert, labeled_service_account):
  if not isinstance(istio_ca_cert, IstioCACert):
    raise TypeError('Invalid type: istio_ca_cert must be a IstioCACert, not %r' % type(istio_ca_cert))
  if not isinstance(labeled_service_account, LabeledServiceAccount):
    raise TypeError('Invalid type: labeled_service_account must be a LabeledServiceAccount, not %r' % type(labeled_service_account))
  
  try:
    if labeled_service_account.cert_type == "pem":
      cert_pem = base64.b64decode(K8S.read_namespaced_secret(labeled_service_account.cert_secret_name, labeled_service_account.namespace).data["cert.pem"]).decode()
      cert_info = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    elif labeled_service_account.cert_type == "pkcs12":
      cert_pkcs12 = base64.b64decode(K8S.read_namespaced_secret(labeled_service_account.cert_secret_name, labeled_service_account.namespace).data["cert.p12"])
      cert_info = load_key_and_certificates(cert_pkcs12, password=labeled_service_account.cert_pkcs12_password.encode(), backend=default_backend())[1]
    else:
      return

    if int((datetime.datetime.utcnow() - cert_info.not_valid_before).total_seconds()) > labeled_service_account.cert_ttl:
      updated_workload_cert = IstioWorkloadCert(istio_ca_cert=istio_ca_cert, labeled_service_account=labeled_service_account)
      secret = generate_cert_secret(labeled_service_account=labeled_service_account, worload_cert=updated_workload_cert)
      K8S.patch_namespaced_secret(labeled_service_account.cert_secret_name, labeled_service_account.namespace, secret)
      print(f"Updated {labeled_service_account.cert_type} certificate secret '{labeled_service_account.cert_secret_name}' for serviceaccount '{labeled_service_account.name}' in namespace '{labeled_service_account.namespace}'")
  except client.exceptions.ApiException:
    new_workload_cert = IstioWorkloadCert(istio_ca_cert=istio_ca_cert, labeled_service_account=labeled_service_account)
    secret = generate_cert_secret(labeled_service_account=labeled_service_account, worload_cert=new_workload_cert)
    K8S.create_namespaced_secret(labeled_service_account.namespace, secret)
    print(f"Created {labeled_service_account.cert_type} certificate secret '{labeled_service_account.cert_secret_name}' for serviceaccount '{labeled_service_account.name}' in namespace '{labeled_service_account.namespace}'")


def generate_cert_secret(*, labeled_service_account, worload_cert):
  if not isinstance(worload_cert, IstioWorkloadCert):
    raise TypeError('Invalid type: istio_ca_cert must be a IstioWorkloadCert, not %r' % type(worload_cert))
  if not isinstance(labeled_service_account, LabeledServiceAccount):
    raise TypeError('Invalid type: labeled_service_account must be a LabeledServiceAccount, not %r' % type(labeled_service_account))
  
  if labeled_service_account.cert_type == "pem":
    data = {
      "key.pem": base64.b64encode(worload_cert.get_pem_data()[0].encode()).decode(),
      "cert.pem": base64.b64encode(worload_cert.get_pem_data()[1].encode()).decode(),
      "cert-chain.pem": base64.b64encode(worload_cert.get_pem_data()[2].encode()).decode()
    }
  elif labeled_service_account.cert_type == "pkcs12":
    data = {
      "cert.p12": base64.b64encode(worload_cert.get_pkcs12_data(name=labeled_service_account.name,password=labeled_service_account.cert_pkcs12_password)).decode()
    }
  else:
    return

  return client.V1Secret(
    api_version="v1",
    data=data,
    kind="Secret",
    metadata=dict(name=labeled_service_account.cert_secret_name, namespace=labeled_service_account.namespace)
  )


def main(argv):
  print(f"Daemon started (poll interval {POLL_INTERVAL}s)")

  try:
    config.load_incluster_config()
  except config.ConfigException:
    try:
      config.load_kube_config()
    except config.ConfigException:
      raise Exception("Could not configure kubernetes python client")

  global K8S
  K8S = client.CoreV1Api()

  trust_domain = get_trust_domain()
  istio_ca_secret = get_istio_ca_secret()
  istio_ca_cert = IstioCACert(istio_ca_secret=istio_ca_secret, trust_domain=trust_domain)

  while True:
    for ns in get_namespaces():
      for sa_labeled in get_serviceaccounts(namespace=ns):
        check_refresh_certificate(labeled_service_account=sa_labeled, istio_ca_cert=istio_ca_cert)
    sleep(POLL_INTERVAL)

if __name__ == "__main__":
  main(sys.argv[1:])
