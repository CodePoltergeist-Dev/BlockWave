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
        Monitors incoming traffic, simulates DDoS attack, and checks against thresholds.
        """
        try:
            while True:
                # Simulate incoming traffic
                if random.random() < 1.0:  # 10% chance to simulate DDoS
                    simulated_ip = self.simulate_incoming_ip()
                    self.simulate_ddos_attack(simulated_ip)
                else:
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

        except ClientError as e:
            logger.error(f"Error getting traffic data: {e}")
            self.log_area.insert(tk.END, f"Error getting traffic data: {e}\n")

    def simulate_incoming_ip(self):
        """
        Simulates incoming IP addresses. You can add more variety to the IPs for demonstration.
        """
        simulated_ip = f"192.168.1.{random.randint(1, 255)}"
        return simulated_ip

    def simulate_ddos_attack(self, ip):
        """
        Simulates DDoS attack by generating multiple requests from a single IP.
        """
        for _ in range(150):  # Simulate 150 requests
            self.check_traffic(ip, np.random.rand(10), "simulated")

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
        Initiates mitigation by blocking the offending IP after rate limiting.
        """
        logger.info(f"Mitigating attack from IP: {ip}")
        self.log_area.insert(tk.END, f"Mitigating attack from IP: {ip}\n")
        self.block_ip(ip)

    def block_ip(self, ip):
        """
        Blocks the IP address by modifying the cloud security group rules.
        """
        try:
            ec2.revoke_security_group_ingress(
                GroupId='sg-04ced552176c45a0b',  # Replace with your security group ID
                IpProtocol='tcp',
                FromPort=80,
                ToPort=80,
                CidrIp=f'{ip}/32'
            )
            logger.info(f"Blocked IP: {ip}")
            self.log_area.insert(tk.END, f"Blocked IP: {ip}\n")

            # Unblock the IP after the block duration
            Timer(BLOCK_DURATION, self.unblock_ip, args=[ip]).start()

        except ClientError as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            self.log_area.insert(tk.END, f"Failed to block IP {ip}: {e}\n")

    def unblock_ip(self, ip):
        """
        Unblocks the IP address after the block duration has passed.
        """
        try:
            ec2.authorize_security_group_ingress(
                GroupId='sg-04ced552176c45a0b',  # Replace with your security group ID
                IpProtocol='tcp',
                FromPort=80,
                ToPort=80,
                CidrIp=f'{ip}/32'
            )
            blacklist.remove(ip)
            logger.info(f"Unblocked IP: {ip}")
            self.log_area.insert(tk.END, f"Unblocked IP: {ip}\n")

        except ClientError as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            self.log_area.insert(tk.END, f"Failed to unblock IP {ip}: {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSProtectionApp(root)
    root.mainloop()
