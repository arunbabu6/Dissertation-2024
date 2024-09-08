#Execve Syscall Monitoring using BCC#
from bcc import BPF
import watchtower
import logging
import logging.handlers
import traceback
import signal
import time

# Set up logging to CloudWatch and a local file with rotation
logging.basicConfig(level=logging.INFO, handlers=[
    watchtower.CloudWatchLogHandler(log_group='bcc-alerts', stream_name='execve-monitoring')
])

log_file = 'execve_monitoring.log'
log_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=3)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logging.root.addHandler(log_handler)

# Local log file
local_log_file = '/var/log/bcc.log'
local_log_handler = logging.handlers.RotatingFileHandler(local_log_file, maxBytes=10*1024*1024, backupCount=3)
local_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logging.root.addHandler(local_log_handler)

# Define BPF program
bpf_program = """
int trace_execve(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("execve: %s\\n", comm);
    return 0;
}
"""

# Compile and attach the BPF program
def attach_bpf_program():
    try:
        b = BPF(text=bpf_program)
        b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")
        logging.info("BPF program attached successfully.")
        return b
    except Exception as e:
        logging.error(f"Failed to attach BPF program: {e}")
        logging.error(traceback.format_exc())
        raise

# Signal handler for timeout
def signal_handler(signum, frame):
    logging.info("Timeout reached. Stopping execve monitoring...")
    raise TimeoutError("Monitoring timed out")

def main():
    logging.info("Starting execve monitoring (demo setup)...")

    b = attach_bpf_program()

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(200)  # 200 seconds timeout

    try:
        while True:
            try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields()
                logging.info(f"execve detected: pid={pid}, timestamp={ts}, command='{msg}'")
            except KeyboardInterrupt:
                logging.info("Stopping execve monitoring...")
                break
            except Exception as e:
                logging.error(f"Error processing event: {e}")
                logging.error(traceback.format_exc())
    except TimeoutError:
        logging.info("Execve monitoring timed out. Exiting.")
    except Exception as main_e:
        logging.error(f"Fatal error in monitoring loop: {main_e}")
        logging.error(traceback.format_exc())
    finally:
        logging.info("Detaching BPF program.")
        b.cleanup()
        signal.alarm(0)  # disable alarm

if __name__ == "__main__":
    main()
