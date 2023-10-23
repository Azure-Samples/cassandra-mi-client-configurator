import argparse
import logging
import logging.config
import os
import stat
import shutil
import subprocess
import uuid
import tarfile

from azure.core.exceptions import (
    ResourceExistsError,
    ResourceNotFoundError
)
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.cosmosdb.models import (
    ClusterResource,
    ClusterResourceProperties,
    SeedNode,
    Certificate,
    DataCenterResource,
    DataCenterResourceProperties
)
from azure.mgmt.resource import ResourceManagementClient

for _ in logging.root.manager.loggerDict:
    logging.getLogger(_).setLevel(logging.CRITICAL)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s')

parser = argparse.ArgumentParser()

# Cluster args
parser.add_argument('--subscription-id', type=str, required=True, help='Subscription ID of the Azure managed cluster')
parser.add_argument('--cluster-resource-group', type=str, required=True, help='Resource group of the Azure managed cluster')
parser.add_argument('--cluster-name', type=str, required=True, help='Cluster name of the Azure managed cluster')
parser.add_argument('--cluster-name-override', type=str)
parser.add_argument('--initial-password', type=str, required=True)
parser.add_argument('--location', type=str, required=True, help='Location of the Azure managed cluster')
parser.add_argument('--seed-nodes', nargs='+', type=str, required=True, help='Seed nodes of existing cluster')

# Data center args
parser.add_argument('--data-center-name', type=str, required=True, help='Data center name of the Azure managed cluster')
parser.add_argument('--node-count', type=int, default=3, help='Node count of the Azure managed cluster')
parser.add_argument('--sku', type=str, required=True, help='SKU to use for the nodes of the Azure managed cluster')
parser.add_argument('--disk-capacity', type=int, default=4, help='Disk capacity for each node of the Azure managed cluster')

# VNet args
parser.add_argument('--vnet-resource-group', type=str, required=True, help='Resource group of the virtual network')
parser.add_argument('--vnet-name', type=str, required=True, help='Name of the virtual network')
parser.add_argument('--subnet-name', type=str, required=True, help='Name of the subnet delegated to the Azure managed cluster')
parser.add_argument('--skip-role-assignment', action='store_true', help='Skip creating role assignment for Azure Cosmos DB to access the virtual network')

# Gossip certificate args
parser.add_argument('--keystore-pass', type=str, default='changeme', help='Password for the keystore to be installed on the on-prem nodes')
parser.add_argument('--keystore-owner', type=str, default='cassandra:cassandra', help='Owner of the keystore to be installed on the on-prem nodes')

args = parser.parse_args()
subscription_id = args.subscription_id
cluster_resource_group = args.cluster_resource_group
cluster_name = args.cluster_name
cluster_name_override = args.cluster_name_override
initial_password = args.initial_password
location = args.location
seed_nodes = args.seed_nodes
data_center_name = args.data_center_name
node_count = args.node_count
sku = args.sku
disk_capacity = args.disk_capacity
vnet_resource_group = args.vnet_resource_group
vnet_name = args.vnet_name
subnet_name = args.subnet_name
skip_role_assignment = args.skip_role_assignment
keystore_pass = args.keystore_pass
keystore_owner = args.keystore_owner

vnet_id=f'/subscriptions/{subscription_id}/resourceGroups/{vnet_resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}'
subnet_id=f'{vnet_id}/subnets/{subnet_name}'

# Create a role assignment for Azure Cosmos DB to access the virtual network
if skip_role_assignment:
    logging.warning(f'Skipping role assignment creation for {vnet_id}, to assign the role manually run the following command:')
    logging.warning(f'az role assignment create --assignee a232010e-820c-4083-83bb-3ace5fc29d0b --role 4d97b98b-1d4f-4787-a291-c67834d212e7 --scope {vnet_id}')
else:
    logging.info(f'Creating role assignment for Azure Cosmos DB to access the virtual network {vnet_id}')
    with AuthorizationManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id) as auth_client:
        try:
            role_assignment = auth_client.role_assignments.create(
                scope=vnet_id,
                role_assignment_name=str(uuid.uuid4()),
                parameters={
                    'role_definition_id':'/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7',
                    'principal_id':'e5007d2c-4b13-4a74-9b6a-605d99f03501'
                }
            )        
            logging.info(f'Role assignment created {str(role_assignment)}')
        except ResourceExistsError as e:
            logging.warning(str(e))
        except Exception as e:
            logging.error(f'Role assignment create failed with exception {e}')
            raise e

# Create resource group for the cluster
with ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id) as resource_client:
    try:
        resource_client.resource_groups.get(resource_group_name=cluster_resource_group)
        logging.warning(f'Using existing resource group {cluster_resource_group}')        
    except ResourceNotFoundError as e:
        logging.info(f'Creating resource group {cluster_resource_group} in location {location}')       
        resource_client.resource_groups.create_or_update(
            resource_group_name=cluster_resource_group,
            parameters={'location': location}
        )
        logging.info(f'Resource group {cluster_resource_group} created')
    except Exception as e:
        logging.error(f'Resource group create failed with exception {e}')
        raise e

with CosmosDBManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id) as cosmosdb_client:
    cert_dir = f'{os.getcwd()}/cassandra_mi_migration'
    if os.path.exists(cert_dir):
        logging.warning(f'Deleting existing certs directory {cert_dir}')
        shutil.rmtree(cert_dir)

    logging.info(f'Creating certs directory {cert_dir}')
    os.makedirs(cert_dir)
    os.chdir(cert_dir)

    # Create the cluster with seed nodes from unmanaged cluster and gossip certificates
    cluster = None
    try:
        response = cosmosdb_client.cassandra_clusters.get(
            resource_group_name=cluster_resource_group,
            cluster_name=cluster_name
        )
        cluster = response.properties
        logging.warning(f'Using existing cluster {cluster_name} in resource group {cluster_resource_group}')
    except ResourceNotFoundError as e:
        logging.info(f'Creating cluster {cluster_name} in resource group {cluster_resource_group} in location {location}')
        response = cosmosdb_client.cassandra_clusters.begin_create_update(
                resource_group_name=cluster_resource_group,
                cluster_name=cluster_name,
                body=ClusterResource(
                    location=location,
                    properties=ClusterResourceProperties(
                        cluster_name_override=cluster_name_override,
                        delegated_management_subnet_id=subnet_id,
                        initial_cassandra_admin_password=initial_password                        
                    )
                )
            )
        response.wait()
        cluster = response.result().properties
        logging.info(f'Cluster created: {str(response.result().properties)}')
    except Exception as e:
        logging.error(f'Cluster create failed with exception {e}')
        raise e
    
    # Create the data center with the given name, node count, sku, and disk capacity
    try:
        response = cosmosdb_client.cassandra_data_centers.get(
            resource_group_name=cluster_resource_group,
            cluster_name=cluster_name,
            data_center_name=data_center_name
        )
        logging.warning(f'Using existing data center {data_center_name} in cluster {cluster_name} in resource group {cluster_resource_group}')
    except ResourceNotFoundError as e:
        logging.info(f'Creating data center {data_center_name} in cluster {cluster_name} in resource group {cluster_resource_group}')
        response = cosmosdb_client.cassandra_data_centers.begin_create_update(
            resource_group_name=cluster_resource_group,
            cluster_name=cluster_name,
            data_center_name=data_center_name,
            body=DataCenterResource(
                properties=DataCenterResourceProperties(
                    delegated_subnet_id=subnet_id,
                    data_center_location=location,
                    node_count=node_count,
                    sku=sku,
                    disk_capacity=disk_capacity
                )
            )
        )
        response.wait()
        logging.info(f'Data center created: {str(response.result().properties)}')
    except Exception as e:
        logging.error(f'Data center create failed with exception {e}')
        raise e
    
    # Get the cluster details from the created cluster and copy the gossip certificates
    logging.info(f'Getting gossip certificates for cluster {cluster_name}')
    managed_cluster_certs = []
    try:
        cluster = cosmosdb_client.cassandra_clusters.get(
            resource_group_name=cluster_resource_group,
            cluster_name=cluster_name
        )                        
        managed_cluster_certs = cluster.properties.gossip_certificates
        logging.info(f'Retrieved {len(managed_cluster_certs)} gossip certificates')
    except Exception as e:
        logging.error(f'Cluster get failed with exception {e}')
        raise e

    logging.info(f'Creating files for each Managed Cassandra cert...')
    for cert in cluster.properties.gossip_certificates:
            cert_alias = str(uuid.uuid4())
            with open(f'{cert_alias}.pem', 'w+') as f:
                f.write(cert.pem)
                f.flush()

                logging.info(f'Importing {cert_alias} into truststore')
                subprocess.run(['keytool', '-import', '-trustcacerts', '-alias', cert_alias, '-file', f'{cert_alias}.pem', '-keystore', 'n2n_truststore.keystore', '-storepass', keystore_pass, '-noprompt'])
    logging.info(f'Done')

    # Create keystore and truststore
    logging.info(f'Creating self-signed certificate for gossip encryption')
    logging.info(f'Generating private/public key pair using keytool')
    subprocess.run(['keytool',
                    '-genkey',
                    '-keyalg', 'RSA',
                    '-alias', 'gossip',
                    '-validity', '36500',
                    '-keystore', 'n2n_server.keystore',
                    '-storepass', keystore_pass,
                    '-keypass', keystore_pass,
                    '-dname', 'CN=gossipKeyStore'])

    logging.info(f'Exporting public key from key store')
    subprocess.run(['keytool', '-export', '-rfc', '-alias', 'gossip', '-file', 'gossip_public.pem', '-keystore', 'n2n_server.keystore', '-storepass', keystore_pass, '-noprompt'])

    # Import the on-prem certs into the truststore
    logging.info(f'Importing on-prem public key into truststore')
    subprocess.run(['keytool', '-import', '-trustcacerts', '-alias', 'gossip', '-file', 'gossip_public.pem', '-keystore', 'n2n_truststore.keystore', '-storepass', keystore_pass, '-noprompt'])

    logging.info(f'Creating tar file for installing certs on the on-prem nodes')
    # Creating cert installation script
    with open('install_certs.sh', 'w+') as f:
        f.write(f'''#!/bin/bash
    set -euo pipefail

    seeds={','.join([seed_node.ip_address for seed_node in cluster.properties.seed_nodes])}

    if grep -q $seeds cassandra.yaml; then
        echo "Seed nodes already added to cassandra.yaml"
    else
        echo "Adding managed instance seeds node to cassandra.yaml"   
        sed -i "/^ *- seeds:/ s/\\"$/,${{seeds}}\\"/" cassandra.yaml
    fi

    echo "Setting cassandra user owner on truststore and keystore"
    chown {keystore_owner} /etc/cassandra/n2n_truststore.keystore
    chown {keystore_owner} /etc/cassandra/n2n_server.keystore

    echo "Setting server_encryption_options in cassandra.yaml"
    echo "server_encryption_options:
    internode_encryption: all
    keystore: /etc/cassandra/n2n_server.keystore
    keystore_password: {keystore_pass}
    truststore: /etc/cassandra/n2n_truststore.keystore
    truststore_password: {keystore_pass}
    algorithm: PKIX" >> cassandra.yaml

    while true; do
        read -p "Would you like to restart Cassandra for changes to take effect? (y/n) " choice
        case "$choice" in
        y|Y )
            echo "Restarting Cassandra..."
            systemctl restart cassandra
            echo "Done."
            break
            ;;
        n|N )
            echo "Cassandra will not be restarted."
            break
            ;;
        * )
            echo "Invalid input. Please enter y or n."
            ;;
        esac
    done''')
        
        # Make the script executable
        st = os.stat(f.name)
        os.chmod(f.name, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    with tarfile.open('install_certs.tar.gz', 'w:gz') as archive:
        archive.add('n2n_server.keystore')
        archive.add('n2n_truststore.keystore')
        archive.add('install_certs.sh')

    # Update the managed cluster with the new external certs and seed nodes
    logging.info(f'Updating cluster {cluster_name} with new external certificate.')
    with open('gossip_public.pem', 'r') as gossip_certificates_file:
        try:
            response = cosmosdb_client.cassandra_clusters.begin_create_update(
                resource_group_name=cluster_resource_group,
                cluster_name=cluster_name,
                body=ClusterResource(
                    location=location,
                    properties=ClusterResourceProperties(
                        delegated_management_subnet_id=subnet_id,                     
                        gossip_certificates=managed_cluster_certs,
                        external_seed_nodes=[SeedNode(ip_address=seed_node) for seed_node in seed_nodes],
                        external_gossip_certificates=[Certificate(pem=gossip_certificates_file.read())]
                    )
                )
            )
            response.wait()
            logging.info(f'Managed cluster updated with external certificate.')
        except Exception as e:
            logging.error(f'Cluster update failed with exception {e}')
            raise e