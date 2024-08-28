import os
import time
import logging
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import tkinter as tk
from tkinter import messagebox, scrolledtext
from botocore.exceptions import ClientError
from collections import defaultdict
from threading import Timer
import boto3
import random
import socket
import requests

# Initialize AWS clients (ensure your credentials are set up properly)
ec2 = boto3.client('ec2', region_name='eu-north-1')
autoscaling = boto3.client('autoscaling', region_name='eu-north-1')  # Initialize Auto Scaling client

# Initialize logging
logging.basicConfig(filename='ddos_protection.log', level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger()

# Data structures to track IP traffic and blacklist
ip_traffic = defaultdict(int)
blacklist = set()
rate_limited_ips = defaultdict(lambda: {"count": 0, "start_time": time.time()})
request_times = defaultdict(list)

# Thresholds and configurations
REQUEST_THRESHOLD = 100  # Max requests per IP in a time window
TIME_WINDOW = 60  # Time window in seconds
BLOCK_DURATION = 300  # Block IP for 5 minutes
RATE_LIMIT_THRESHOLD = 20  # Max requests allowed after filtering
RATE_LIMIT_DURATION = 10  # Time window for rate limiting in seconds
DDoS_THRESHOLD = 150  # Number of requests in a single second to classify as DDoS
RECOVERY_WINDOW = 600  # Time window to monitor for recovery (in seconds)
NORMAL_TRAFFIC_THRESHOLD = 10  # Max requests per IP for recovery phase

# Load and preprocess historical data (dummy data for the example)
df = pd.read_csv('main.csv')
df_numeric = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'])
df_numeric = pd.get_dummies(df_numeric, columns=['Protocol'])
X = df_numeric.drop(columns=['Label'])
y = df_numeric['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Load the trained Random Forest model
rf_model = joblib.load('random_forest_model.pkl')

def get_ip_geo_location(ip):
    """
    Fetches geo-location information for a given IP address.
    """
    try:
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to get geo-location for IP {ip}: {e}")
        return {"error": str(e)}

# GUI setup
class DDoSProtectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DDoS Protection System")
        self.root.geometry("800x700")

        # Website IP input
        self.label = tk.Label(root, text="Enter Website IP to Monitor:")
        self.label.pack(pady=10)

        self.ip_entry = tk.Entry(root, width=30)
        self.ip_entry.pack(pady=10)

        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=10)

        # Log output
        self.log_area = scrolledtext.ScrolledText(root, width=70, height=20)
        self.log_area.pack(pady=10)

        # Real-time metrics
        self.metrics_label = tk.Label(root, text="Real-time Metrics:")
        self.metrics_label.pack(pady=10)

        self.metrics_text = tk.Text(root, width=40, height=10)
        self.metrics_text.pack(pady=10)

        # DDoS attack status
        self.attack_status_label = tk.Label(root, text="Website Status: Normal")
        self.attack_status_label.pack(pady=10)

    def start_monitoring(self):
        website_ip = self.ip_entry.get()
        if not website_ip:
            messagebox.showerror("Input Error", "Please enter a valid website IP.")
            return

        self.log_area.insert(tk.END, f"Monitoring started for website IP: {website_ip}\n")
        self.monitor_traffic(website_ip)

    def monitor_traffic(self, website_ip):
        """
        Monitors incoming traffic, checks against thresholds, and manages self-healing.
        """
        try:
            while True:
                simulated_ip = self.simulate_incoming_ip()
                ip_features = np.random.rand(10)  # Replace with actual feature extraction logic
                self.log_area.insert(tk.END, f"Incoming IP: {simulated_ip}\n")
                self.check_traffic(simulated_ip, ip_features, website_ip)

                # Update GUI with real-time metrics
                self.metrics_text.delete(1.0, tk.END)
                self.metrics_text.insert(tk.END, f"Incoming traffic: {sum(ip_traffic.values())} requests\n")
                self.metrics_text.insert(tk.END, f"IPs being monitored: {len(ip_traffic)}\n")
                self.metrics_text.insert(tk.END, f"Blacklisted IPs: {len(blacklist)}\n")

                self.log_area.insert(tk.END, f"Traffic monitoring update: {time.time()}\n")
                self.root.update()
                time.sleep(1)

                self.check_for_recovery()  # Check if the system is recovering from DDoS attack

        except ClientError as e:
            logger.error(f"Error getting traffic data: {e}")
            self.log_area.insert(tk.END, f"Error getting traffic data: {e}\n")

    def simulate_incoming_ip(self):
        """
        Simulates incoming IP addresses. You can add more variety to the IPs for demonstration.
        """
        simulated_ip = f"192.168.1.{random.randint(1, 255)}"
        return simulated_ip

    def check_traffic(self, ip, ip_features, website_ip):
        """
        Checks and processes the traffic for a given IP address.
        """
        current_time = time.time()
        ip_traffic[ip] += 1
        request_times[ip].append(current_time)

        # Remove timestamps older than 1 second
        request_times[ip] = [t for t in request_times[ip] if t > current_time - 1]

        # Check for DDoS attack
        if len(request_times[ip]) > DDoS_THRESHOLD:
            self.attack_status_label.config(text="Website Status: 🚨 Potential DDoS Attack 🚨", fg="red")
            self.log_area.insert(tk.END, f"Potential DDoS attack detected from IP: {ip}\n")
            self.filter_and_rate_limit(ip)
        else:
            self.attack_status_label.config(text="Website Status: Normal", fg="green")

        if ip in blacklist:
            return

        if ip_traffic[ip] > REQUEST_THRESHOLD:
            logger.warning(f"Suspicious activity detected from IP: {ip}")
            if self.predict_anomaly(ip_features):
                logger.info(f"Anomaly detected from IP: {ip}")
                self.log_area.insert(tk.END, f"Anomaly detected from IP: {ip}\n")
                self.filter_and_rate_limit(ip)
            else:
                logger.info(f"Traffic from IP: {ip} is not anomalous.")

        Timer(TIME_WINDOW, lambda: ip_traffic.pop(ip, None)).start()

    def predict_anomaly(self, ip_features):
        """
        Predicts if an IP's traffic is anomalous using the trained Random Forest model.
        """
        prediction = rf_model.predict([ip_features])
        return prediction[0] == 1  # Assuming 1 indicates an anomaly

    def filter_and_rate_limit(self, ip):
        """
        Filters and rate-limits suspicious IPs instead of outright blocking them.
        """
        current_time = time.time()
        rate_limit_info = rate_limited_ips[ip]

        if current_time - rate_limit_info["start_time"] <= RATE_LIMIT_DURATION:
            rate_limit_info["count"] += 1
        else:
            rate_limit_info["count"] = 1
            rate_limit_info["start_time"] = current_time

        if rate_limit_info["count"] > RATE_LIMIT_THRESHOLD:
            blacklist.add(ip)
            logger.info(f"Rate limiting applied to IP: {ip}")
            self.log_area.insert(tk.END, f"Rate limiting applied to IP: {ip}\n")
            self.mitigate_attack(ip)
        else:
            logger.info(f"Filtered IP: {ip} - Request count: {rate_limit_info['count']}")
            self.log_area.insert(tk.END, f"Filtered IP: {ip} - Request count: {rate_limit_info['count']}\n")

    def mitigate_attack(self, ip):
        """
        Initiates mitigation by blocking the offending IP in AWS Security Groups.
        """
        try:
            response = ec2.revoke_security_group_ingress(
                GroupId='sg-xxxxxxxx',  # Replace with your Security Group ID
                IpProtocol='-1',
                CidrIp=f"{ip}/32"
            )
            logger.info(f"Blocked IP: {ip} via AWS Security Group")
            self.log_area.insert(tk.END, f"Blocked IP: {ip} via AWS Security Group\n")
        except ClientError as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            self.log_area.insert(tk.END, f"Error blocking IP {ip}: {e}\n")

    def check_for_recovery(self):
        """
        Checks if the traffic patterns indicate the DDoS attack has subsided, and initiates recovery.
        """
        current_time = time.time()
        recovery_ips = [ip for ip, timestamps in request_times.items()
                        if len(timestamps) <= NORMAL_TRAFFIC_THRESHOLD and ip in blacklist]

        if recovery_ips:
            for ip in recovery_ips:
                if current_time - min(request_times[ip]) > RECOVERY_WINDOW:
                    self.recover_ip(ip)

    def recover_ip(self, ip):
        """
        Recovers the IP by unblocking it in AWS and removing it from the blacklist.
        """
        try:
            response = ec2.authorize_security_group_ingress(
                GroupId='sg-xxxxxxxx',  # Replace with your Security Group ID
                IpProtocol='-1',
                CidrIp=f"{ip}/32"
            )
            blacklist.remove(ip)
            logger.info(f"Recovered IP: {ip} via AWS Security Group")
            self.log_area.insert(tk.END, f"Recovered IP: {ip} via AWS Security Group\n")
            self.attack_status_label.config(text="Website Status: Recovered", fg="green")
        except ClientError as e:
            logger.error(f"Error recovering IP {ip}: {e}")
            self.log_area.insert(tk.END, f"Error recovering IP {ip}: {e}\n")

# Initialize the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSProtectionApp(root)
    root.mainloop()
