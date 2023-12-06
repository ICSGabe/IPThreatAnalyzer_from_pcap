# Import necessary libraries
import pyshark
import requests
import ipaddress
import json

# Function to extract public IPs from a PCAP file
def extract_public_ips_from_pcap(pcap_file_path):
    # Initialize a set to store unique public IPs
    public_ips = set()
    # Open the pcap file for reading
    cap = pyshark.FileCapture(pcap_file_path)

    # Iterate over each packet in the pcap file
    for packet in cap:
        try:
            # Check if the packet contains IP information
            if 'IP' in packet:
                # Extract source and destination IP addresses
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                # Check if the source IP is not a private address and add it to the set
                if not ipaddress.ip_address(src_ip).is_private:
                    public_ips.add(src_ip)
                # Check if the destination IP is not a private address and add it to the set
                if not ipaddress.ip_address(dst_ip).is_private:
                    public_ips.add(dst_ip)
        except AttributeError:
            # If there is an error (e.g., no IP layer), continue to the next packet
            continue
    # Close the pcap file
    cap.close()
    # Return the set of public IP addresses
    return public_ips

# Function to check an IP against AlienVault OTX
def check_ip_alienvault(ip, av_api_key):
    # Set the request headers with the API key
    headers = {
        "X-OTX-API-KEY": av_api_key
    }
    # Format the API URL with the IP address
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    # Make the HTTP request to the API
    response = requests.get(url, headers=headers)
    # If the response is successful
    if response.status_code == 200:
        # Parse the response as JSON
        data = response.json()
        # Check if there are any pulses (threat reports) associated with the IP
        if data['pulse_info']['count'] > 0:
            # Return True (malicious) and the associated pulses
            return True, data['pulse_info']['pulses']
        else:
            # Return False (not malicious) and None for pulses
            return False, None
    else:
        # If the API request failed, return False and None
        return False, None

# Function to check an IP against VirusTotal
def check_ip_virustotal(ip, vt_api_key):
    # Format the VirusTotal API URL for the IP address
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    # Set the request headers with the API key
    headers = {
        "x-apikey": vt_api_key
    }
    # Make the HTTP request to the API
    response = requests.get(url, headers=headers)
    # If the response is successful
    if response.status_code == 200:
        # Parse the response as JSON
        data = response.json()
        # Get the count of malicious votes for the IP
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        # If there are any malicious votes, return True (malicious)
        if malicious_votes > 0:
            return True
        else:
            # Otherwise, return False (not malicious)
            return False
    else:
        # If the API request failed, return False
        return False

# Main function to run the script
def main():
    # Prompt the user for the necessary input
    pcap_file_path = input("Enter the path to your pcap file: ")
    output_file_path = input("Enter the path for the output file: ")
    av_api_key = input("Enter your AlienVault OTX API key: ")
    vt_api_key = input("Enter your VirusTotal API key: ")

    # Extract public IPs from the PCAP file
    public_ips = extract_public_ips_from_pcap(pcap_file_path)

    # Open the output file for writing results
    with open(output_file_path, 'w') as output_file:
        # Check each IP with both AlienVault OTX and VirusTotal
        for ip in public_ips:
            av_is_malicious, av_pulses = check_ip_alienvault(ip, av_api_key)
            vt_is_malicious = check_ip_virustotal(ip, vt_api_key)
            # Write the results to the output file
            if av_is_malicious or vt_is_malicious:
                output_file.write(f"Suspicious IP detected: {ip}\n")
                if av_pulses:
                    output_file.write("Associated AlienVault OTX pulses:\n")
                    for pulse in av_pulses:
                        output_file.write(f"  - {pulse['name']} (ID: {pulse['id']})\n")
                if vt_is_malicious:
                    output_file.write("This IP has been flagged as malicious on VirusTotal.\n")
            else:
                output_file.write(f"No suspicious activity detected for IP: {ip}\n")
            output_file.write('\n')

    # Print a completion message to the console
    print(f"Analysis complete. Results are saved in {output_file_path}")

# Entry point of the script
if __name__ == "__main__":
    main()
