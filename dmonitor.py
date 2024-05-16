import psutil
import time
import logging

# US Government domains to monitor
SUSPICIOUS_DOMAINS = [
    "collector.azure.eaglex.ic.gov",
    "collector.azure.microsoft.scloud",
    "login.microsoftonline.com",
    "dc.services.visualstudio.com",
    "vortex.data.microsoft.com",
    "settings-win.data.microsoft.com"
]

# Configure logging
logging.basicConfig(filename="network_monitor.log", level=logging.INFO)

def monitor_connections():
    while True:
        for process in psutil.process_iter(['pid', 'name', 'connections']):
            for connection in process.info['connections']:
                if connection.status == psutil.CONN_ESTABLISHED:
                    domain = connection.laddr.ip
                    if any(domain in d for d in SUSPICIOUS_DOMAINS):
                        logging.info(
                            f"Process{process.info['name']} (PID {process.info['pid']}) "
                            f"connected to {domain}"
                        )
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    monitor_connections()
