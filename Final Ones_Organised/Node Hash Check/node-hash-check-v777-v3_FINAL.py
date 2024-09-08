import boto3
import subprocess
import logging
import watchtower
import os
import json
from kubernetes import client, config, watch
import tenacity  # For retry mechanism

# AWS configuration
AWS_REGION = 'us-west-2'
os.environ['AWS_REGION'] = AWS_REGION

# Create a boto3 session with an explicit region
session = boto3.Session(region_name=os.environ['AWS_REGION'])

# Initialize AWS Secrets Manager client
SECRETS_MANAGER_CLIENT = session.client('secretsmanager')

# Setup logging
logging.basicConfig(level=logging.INFO, handlers=[
    logging.FileHandler("/var/log/hashcheck.log"),
    watchtower.CloudWatchLogHandler(log_group='deployment-monitoring', stream_name='deployment-monitoring', boto3_client=session.client('logs'))
])

# Load the Kubernetes configuration from the node or from kubeconfig if you're running this outside
config.load_kube_config()

# Create a Kubernetes API client
v1 = client.CoreV1Api()

# Log the current Kubernetes context to verify which account is being used
def log_kubernetes_auth():
    current_context = config.list_kube_config_contexts()[1]
    logging.info(f"Current context: {current_context['context']['user']}")

log_kubernetes_auth()

@tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_attempt(2))
def get_image_hash(pod_name, namespace, build_id):
    try:
        logging.info(f"Fetching image hash for pod {pod_name} in namespace {namespace}")
        cmd = f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.status.containerStatuses[0].image}}'"
        output = subprocess.check_output(cmd, shell=True)
        image_url = output.decode('utf-8').strip()
        logging.info(f"Image URL: {image_url}")

        # Extract the image ID from the image URL
        image_id = image_url.split(':')[1].split('@')[0]
        logging.info(f"Image ID: {image_id}")

        return image_id
    except Exception as e:
        logging.error(f"Error fetching image hash for pod {pod_name}: {e}")
        return None
    
def verify_image_hash(pod_name, namespace, build_id):
    """Verifies the container image hash against the stored hash."""
    image_hash = get_image_hash(pod_name, namespace, build_id)  # Pass build_id to get_image_hash

    if not image_hash:
        logging.error(f"Cannot verify image hash for pod {pod_name}. Image hash not found.")
        return

    # Fetch the stored hash by build_id (ignoring the timestamp)
    stored_hash = get_stored_hash(build_id)

    if not stored_hash:
        logging.error(f"Cannot verify image hash for pod {pod_name}. Stored hash not found.")
        return

    # Compare the hash and take action
    if image_hash == stored_hash:
        logging.info(f"Pod {pod_name}: Image hash verified successfully.")
    else:
        logging.warning(f"Pod {pod_name}: Image hash verification failed. Stopping the pod.")
        stop_container(pod_name, namespace)


def monitor_pods():
    """Monitors pod creation events and verifies image hash."""
    w = watch.Watch()
    try:
        for event in w.stream(v1.list_pod_for_all_namespaces):
            if event['type'] == 'ADDED':
                pod = event['object']
                pod_name = pod.metadata.name
                namespace = pod.metadata.namespace
                labels = pod.metadata.labels or {}

                # Log metadata and labels for better debugging
                logging.info(f"Pod {pod_name} detected with labels: {labels}")

                build_id = labels.get('build_id')

                if not build_id:
                    logging.error(f"Pod {pod_name} does not have a build_id label. Skipping image hash verification.")
                    continue

                # Verify the image hash if build_id is available
                logging.info(f"New pod detected: {pod_name} in namespace {namespace} with build_id {build_id}")
                verify_image_hash(pod_name, namespace, build_id)
    except Exception as e:
        logging.error(f"Error occurred while monitoring pods: {e}")


def get_stored_hash(build_id):
    """Search for the latest secret with the given build_id in Secrets Manager."""
    try:
        secret_prefix = f"ImageHash-{build_id}"
        logging.info(f"Searching Secrets Manager for secret with prefix: {secret_prefix}")

        # List all secrets and filter those starting with the secret_prefix
        secrets = SECRETS_MANAGER_CLIENT.list_secrets()['SecretList']
        matching_secrets = [secret for secret in secrets if secret['Name'].startswith(secret_prefix)]

        if not matching_secrets:
            logging.error(f"No secrets found for build_id {build_id}")
            return None

        # Extract the hash value from the secret name (ignoring the timestamp)
        hash_value = [secret['Name'].split('-')[1] for secret in matching_secrets][0]

        logging.info(f"Found secret for build_id {build_id}: {hash_value}")
        return hash_value

    except Exception as e:
        logging.error(f"Error retrieving secret for build_id {build_id} from Secrets Manager: {e}")
        return None

def stop_container(pod_name, namespace):
    """Stops a pod if its hash verification fails."""
    try:
        logging.info(f"Attempting to stop pod {pod_name} in namespace {namespace}")
        v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
        logging.info(f"Stopped pod: {pod_name}")
    except Exception as e:
        logging.error(f"Error stopping pod {pod_name}: {e}")


if __name__ == "__main__":
    logging.info("Starting pod monitoring for image hash verification...")
    monitor_pods()
