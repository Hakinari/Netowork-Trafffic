import sys
import json
import os

# Check if a file path was provided as an argument
if len(sys.argv) < 2:
    print("Usage: python script.py [filepath]")
    sys.exit()

# Get the file path from the command-line argument
file_path = sys.argv[1]

# Create a list to store the URLs and IPs
urls = []
ips = []

# check the file extension
if os.path.splitext(file_path)[1] == '.har':
    # Try loading the file as a HAR file
    with open(file_path) as f:
        har_data = json.load(f)
        for entry in har_data["log"]["entries"]:
            url = entry["request"]["url"]
            ips.append(entry["serverIPAddress"])
            urls.append(url)

elif os.path.splitext(file_path)[1] == '.pcap':
    import pyshark
    capture = pyshark.FileCapture(file_path)
    # Iterate through each packet in the capture
    for packet in capture:
        try:
            # Check if the packet is HTTP or HTTPS
            if packet.transport_layer == 'TCP':
                # Extract the URL and IP from the packet
                url = packet.http.request_full_uri
                ip = packet.ip.dst
                # Append the URL and IP to the lists
                urls.append(url)
                ips.append(ip)
        except AttributeError:
            # ignore packets that don't have the required attributes
            pass

else:
    print("File format not supported")
    sys.exit()

# Create a set from the lists to remove duplicates
urls = list(set(urls))
ips = list(set(ips))

# Write the URLs to a text file
with open("extracted_urls.txt", "w") as f:
    for url in urls:
        f.write(url + "\n")

# Write the IPs to a text file
with open("extracted_ips.txt", "w") as f:
    for ip in ips:
        f.write(ip + "\n")
        


print("All done,"+str(len(urls))+" URLs and "+str(len(ips))+" IPs")
print("Files:\nextracted_ips.txt\nextracted_urls.txt")
print(str(ips))