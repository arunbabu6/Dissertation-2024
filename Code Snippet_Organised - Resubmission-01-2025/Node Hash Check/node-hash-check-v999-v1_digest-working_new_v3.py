import boto3
import subprocess
import logging
import watchtower
import os
# import time
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

# Load the Kubernetes configuration 
config.load_kube_config()

# Create a Kubernetes API client
v1 = client.CoreV1Api()

# Function to log the current Kubernetes context
def log_kubernetes_auth():
    current_context = config.list_kube_config_contexts()[1]
    logging.info(f"Current context: {current_context['context']['user']}")

log_kubernetes_auth()

def wait_for_pod_running(pod_name, namespace):
    for _ in range(10):  
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        if pod.status.phase == "Running":
            return True
        time.sleep(10)  # wait and recheck every 10 seconds
    return False

@tenacity.retry(wait=tenacity.wait_fixed(45), stop=tenacity.stop_after_attempt(6))
def get_image_digest(pod_name, namespace):
    """Fetch the image digest (sha256) for the pod from Kubernetes"""
    try:
        logging.info(f"Fetching image digest for pod {pod_name} in namespace {namespace}")
        
        # Ensure the pod is ready before fetching the image digest
        if not wait_for_pod_running(pod_name, namespace):
            logging.warning(f"Pod {pod_name} did not reach 'Running' state. Skipping digest fetch.")
            return None

        # Fetch the image ID once the pod is ready
        cmd = f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.status.containerStatuses[0].imageID}}'"
        output = subprocess.check_output(cmd, shell=True)
        logging.info(f"Raw output from kubectl: {output}")
        image_id = output.decode('utf-8').strip()

        if not image_id:
            logging.warning(f"No image ID found for pod {pod_name}. Retrying...")
            raise ValueError("Image ID is empty, retrying...")

        # Ensure the image ID contains the sha256 digest
        if '@sha256:' not in image_id:
            logging.error(f"Unexpected format for image ID: {image_id}")
            raise ValueError("Unexpected format for image ID")

        # Extract the sha256 digest from the imageID
        image_digest = image_id.split('@')[-1]
        logging.info(f"Image digest after split: {image_digest}")
        return image_digest
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing kubectl command: {e}")
        return None
    except Exception as e:
        logging.error(f"Error fetching image digest for pod {pod_name}: {e}")
        return None

def verify_image_digest(pod_name, namespace, build_id):
    """Verifies the container image digest against the stored digest."""
    image_digest = get_image_digest(pod_name, namespace)

    if not image_digest:
        logging.error(f"Cannot verify image digest for pod {pod_name}. Image digest not found.")
        return

    # Fetch the stored digest by build_id
    stored_data = get_stored_digest(build_id)

    if not stored_data:
        logging.error(f"Cannot verify image digest for pod {pod_name}. Stored data not found.")
        return

    stored_hash = stored_data.get("hash")
    stored_digest = stored_data.get("digest")

    # Compare the digest and log the result
    if image_digest == stored_digest:
        logging.info(f"Pod {pod_name}: Image digest verified successfully.")
    else:
        logging.warning(f"Pod {pod_name}: Image digest verification failed.")

def monitor_pods():
    """Monitors pod creation events and verifies image digest."""
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

                # Filter by the myapps namespace and the my-app-v3 label
                if namespace != 'myapps' or labels.get('app') != 'my-app-v1':
                    logging.info(f"Skipping pod {pod_name} as it is not in the myapps namespace or not my-app-v1")
                    continue

                build_id = labels.get('build_id')

                if not build_id:
                    logging.error(f"Pod {pod_name} does not have a build_id label. Skipping image digest verification.")
                    continue

                # Verify the image digest if build_id is available
                logging.info(f"New pod detected: {pod_name} in namespace {namespace} with build_id {build_id}")
                verify_image_digest(pod_name, namespace, build_id)
    except Exception as e:
        logging.error(f"Error occurred while monitoring pods: {e}")


def get_stored_digest(build_id):
    """Retrieve the stored image hash and digest from AWS Secrets Manager."""
    try:
        secret_name = f"ImageHash-{build_id}"
        logging.info(f"Retrieving secret value for {secret_name} from Secrets Manager")
        secret_value = SECRETS_MANAGER_CLIENT.get_secret_value(SecretId=secret_name)['SecretString']
        logging.info(f"Stored data for build_id {build_id}: {secret_value}")
        return eval(secret_value)  # Convert the stored string back to a dictionary
    except Exception as e:
        logging.error(f"Error retrieving secret for build_id {build_id} from Secrets Manager: {e}")
        return None

if __name__ == "__main__":
    logging.info("Starting pod monitoring for image digest verification...")
    monitor_pods()
