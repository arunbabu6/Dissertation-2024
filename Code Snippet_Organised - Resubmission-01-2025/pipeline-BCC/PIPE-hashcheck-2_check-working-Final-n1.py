import bcc
import subprocess
import hashlib
import logging
import watchtower
import boto3
import sys
import os
import time

# AWS configuration
#AWS_REGION = os.getenv('AWS_REGION', 'us-west-2')
#if not AWS_REGION:
#    AWS_REGION = "us-west-2" 
# Log the region being used for debugging
#AWS_REGION = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION') or 'us-west-2'
AWS_REGION = 'us-west-2'
boto3_session = boto3.session.Session(region_name=AWS_REGION)
print(f"Using AWS region: {AWS_REGION}")
client = boto3.client('secretsmanager', region_name=AWS_REGION)

# Retrieve the command-line arguments (manual input for now)
if len(sys.argv) != 3:
    print("Usage: python hashcheck.py <build_id> <image_tag>")
    sys.exit(1)

build_id = sys.argv[1]  # manually input build_id, e.g., 132
image_tag = sys.argv[2]  # manually input image tag, e.g., ebpfztn:132
# Use the session to create a CloudWatch Logs client
logs_client = boto3_session.client('logs')
# Setup logging after build_id is defined
logging.basicConfig(level=logging.INFO, handlers=[
    logging.FileHandler("/opt/logs/hashcheck.log"),
    watchtower.CloudWatchLogHandler(
        log_group='ebpf-hashcheck',
        stream_name=f'hashcheck-{build_id}',
#        boto3_session=boto3_session
    )
])
# Function to fetch stored image hash from Secrets Manager
def get_stored_hash(build_id):
    try:
        secret_name = f"ImageHash-{build_id}"
        response = client.get_secret_value(SecretId=secret_name)
        secret = eval(response['SecretString'])  # Convert secret string to dictionary
        return secret.get('digest')
    except Exception as e:
        logging.error(f"Error fetching secret for build_id {build_id}: {e}")
        return None

# Function to run execsnoop and capture container execution details
def run_execsnoop():
    logging.info("Starting execsnoop monitoring...")
    process = subprocess.Popen(["/usr/share/bcc/tools/execsnoop"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in process.stdout:
        line = line.decode('utf-8')
        if "docker" in line:
            logging.info(f"Detected Docker event: {line}")
            process_id = line.split()[1]  # Assuming process ID is in 2nd position (adjust if needed)
            return process_id
    process.wait()

# Function to verify image hash using eBPF
def verify_image_hash(image_tag, build_id):
    try:
        # Get stored hash from AWS Secrets Manager
        stored_hash = get_stored_hash(build_id)
        if not stored_hash:
            logging.error("Stored hash not found.")
            return False

        # Get current image digest using Docker inspect
        image_id = subprocess.check_output(["docker", "images", "-q", image_tag]).decode().strip()
        digest = subprocess.check_output(["docker", "inspect", "--format={{.RepoDigests}}", image_id]).decode().strip()

        # Extract only the actual digest part
        digest = digest.strip('[]')  # Remove any surrounding brackets
        current_hash = digest.split('@')[-1]  # Extract the digest portion after '@'

        logging.info(f"Stored Hash: {stored_hash}")
        logging.info(f"Current Hash: {current_hash}")

        # Compare digests directly
        return current_hash == stored_hash
    except Exception as e:
        logging.error(f"Error verifying image hash: {e}")
        return False

# Main function to run the script
if __name__ == "__main__":
    success = False 
    while True:
        try:
            # Run execsnoop to monitor Docker events
            docker_process = run_execsnoop()
            logging.info(f"Monitoring Docker process {docker_process} for image {image_tag}")

            # Verify the image hash
            if verify_image_hash(image_tag, build_id):
                logging.info("Image hash verified successfully.")
                success = True  # Set the flag to True if successful
                break
            else:
                logging.error("Image hash verification failed.")
                break
            # Sleep for some time before running again (adjust as needed)
         #   time.sleep(10)
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
            time.sleep(10)  # Sleep before retrying in case of an error
    if success:
        exit(0)  # Return 0 if the process was successful
    else:
        exit(1)  # Return a non-zero value if there was an error