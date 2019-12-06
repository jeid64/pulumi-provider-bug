import pulumi
import pulumi_kubernetes
import requests
from pulumi_kubernetes.apps.v1 import Deployment
from pulumi_aws import iam, ec2, eks
from pulumi_kubernetes.core.v1 import ServiceAccount
from requests.adapters import HTTPAdapter
from urllib3 import Retry

ASSUME_ROLE_POLICY_DOC = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"""

def poll_cluster_endpoint(cluster_endpoint):
    if not pulumi.runtime.is_dry_run():
        s = requests.Session()
        s.verify = False
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[ 502, 503, 504 ])
        s.mount('https://', HTTPAdapter(max_retries=retries))
        print(cluster_endpoint)
        s.get(cluster_endpoint)
        print("now its up.")

def generateKubectlConfig(output_list):
    eks_cluster = output_list[0]
    region_name = output_list[1]
    import subprocess
    config = eks_cluster.name.apply(lambda result: subprocess.getoutput(
        "aws eks --region " + region_name + " update-kubeconfig --name " + result + " --dry-run"))
    return config

class EKSCluster(pulumi.ComponentResource):
    # TODO region configurable.
    def __init__(self, cluster_name, opts=None):
        super().__init__('ekscluster:cluster:cluster', cluster_name, None, opts)
        self.cluster_name = cluster_name
        self.nodegroups = []
        self.create_iam_resources()
        self.create_security_group()
        self.create_cluster()
        self.setup_kubernetes_provider()

    def create_iam_resources(self):
        # We create a master role, and attach some policies for it, and allow all egress.
        self.master_role = iam.Role(self.cluster_name + "-master-role",
                                    assume_role_policy=ASSUME_ROLE_POLICY_DOC, opts=pulumi.ResourceOptions(parent=self))
        iam.RolePolicyAttachment(self.cluster_name + "-master-AmazonEKSClusterPolicy",
                                 policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy", role=self.master_role, opts=pulumi.ResourceOptions(parent=self))
        iam.RolePolicyAttachment(self.cluster_name + "-master-AmazonEKSServicePolicy",
                                 policy_arn="arn:aws:iam::aws:policy/AmazonEKSServicePolicy", role=self.master_role, opts=pulumi.ResourceOptions(parent=self))

    def create_security_group(self):
        master_egress_rules = [{"cidr_blocks": ["0.0.0.0/0"],
                                "from_port":0, "protocol":"-1", "to_port":0}]
        # PULUMI DEVS configure your own subnet ID's.
        self.master_security_group = ec2.SecurityGroup(
            self.cluster_name + "-master-securitygroup", egress=master_egress_rules, vpc_id="vpc-229b4f47", opts=pulumi.ResourceOptions(parent=self))

    def create_cluster(self):
        # PULUMI DEVS configure your own subnet ID's.
        vpc_config = {"endpointPrivateAccess": False, "endpointPublicAccess": True, "security_group_ids": [
            self.master_security_group], "subnet_ids": ["subnet-fa9b5d8d", "subnet-d1d878b4"]}
        self.eks_cluster_resource = eks.Cluster(self.cluster_name, name=self.cluster_name,
                                                role_arn=self.master_role.arn, vpc_config=vpc_config, opts=pulumi.ResourceOptions(parent=self))

        self.endpoint = self.eks_cluster_resource.endpoint.apply(poll_cluster_endpoint)

    def setup_kubernetes_provider(self):
        # Now we're gonna configure Pulumi to talk to the controlplane to do k8s stuff.
        eks_parent_opts = pulumi.ResourceOptions(
            parent=self.eks_cluster_resource)
        kubectl_config = pulumi.Output.all(
            self.eks_cluster_resource, "us-west-2", self.endpoint).apply(generateKubectlConfig)
        self.kube_provider = pulumi_kubernetes.Provider(
            self.cluster_name + "-k8s-provider", kubeconfig=kubectl_config, __opts__=eks_parent_opts)


def eks_stuff():
    eks_cluster = EKSCluster("jeid-test-160")
    provider = eks_cluster.kube_provider

    app_labels = { "app": "nginx" }
    provresopts = pulumi.ResourceOptions(
        provider=provider)
    service_account = ServiceAccount("test-service-account2",
                                             metadata={
                                                 "namespace": "kube-system",
                                                 "labels": app_labels
                                             }, opts=provresopts)

    deployment = Deployment(
       "nginx",
       spec={
           "selector": { "match_labels": app_labels },
           "replicas": 1,
           "template": {
               "metadata": { "labels": app_labels
                           },
               "spec": { "containers": [{ "name": "nginx", "image": "nginx" }],
                         'serviceAccountName': service_account.metadata["name"]} # here's where it breaks
           }
       })

eks_stuff()
