import re
import csv
from collections import defaultdict

# Path to the log file
log_file = "sample.log"

# Core Functions
def count_requests_by_ip(log_lines):
    ip_counts = defaultdict(int)
    for line in log_lines:
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            ip_counts[match.group(1)] += 1
    return dict(sorted(ip_counts.items(), key=lambda item: item[1], reverse=True))

def most_frequent_endpoint(log_lines):
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        match = re.search(r'\"[A-Z]+\s(\/\S*)', line)
        if match:
            endpoint_counts[match.group(1)] += 1
    most_frequent = max(endpoint_counts.items(), key=lambda item: item[1])
    return most_frequent, endpoint_counts

def detect_suspicious_activity(log_lines, threshold=10):
    failed_login_counts = defaultdict(int)
    for line in log_lines:
        if re.search(r"401|invalid credentials", line, re.IGNORECASE):
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                failed_login_counts[match.group(1)] += 1
    print("All failed login attempts:", dict(failed_login_counts))  # Debugging
    return {ip: count for ip, count in failed_login_counts.items() if count > threshold}

# Read the log file
with open(log_file, 'r') as file:
    log_lines = file.readlines()

# Analysis
ip_requests = count_requests_by_ip(log_lines)
most_accessed_endpoint, all_endpoints = most_frequent_endpoint(log_lines)
suspicious_activities = detect_suspicious_activity(log_lines)

# Output to Terminal
print("Requests per IP Address:")
print(f"{'IP Address':<20}{'Request Count'}")
for ip, count in ip_requests.items():
    print(f"{ip:<20}{count}")
print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)\n")
print("Suspicious Activity Detected:")
print(f"{'IP Address':<20}{'Failed Login Attempts'}")
for ip, count in suspicious_activities.items():
    print(f"{ip:<20}{count}")

# Save to CSV
output_file = "log_analysis_results.csv"
with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # Requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in ip_requests.items():
        writer.writerow([ip, count])
    
    # Most Accessed Endpoint
    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
    
    # Suspicious Activity
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_activities.items():
        writer.writerow([ip, count])

print(f"\nResults saved to {output_file}")

