import pyshark
import requests
import ipaddress
import json

def extract_public_ips_from_pcap(pcap_file_path):
    public_ips = set()
    cap = pyshark.FileCapture(pcap_file_path)

    for packet in cap:
        try:
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                if not ipaddress.ip_address(src_ip).is_private:
                    public_ips.add(src_ip)
                if not ipaddress.ip_address(dst_ip).is_private:
                    public_ips.add(dst_ip)
        except AttributeError:
            continue
    cap.close()
    return public_ips

def check_ip_alienvault(ip, av_api_key):
    headers = {
        "X-OTX-API-KEY": av_api_key
    }
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data['pulse_info']['count'] > 0:
            return True, data['pulse_info']['pulses']
        else:
            return False, None
    else:
        return False, None

def check_ip_virustotal(ip, vt_api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": vt_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        if malicious_votes > 0:
            return True
        else:
            return False
    else:
        return False

def main():
    pcap_file_path = input("Enter the path to your pcap file: ")
    output_file_path = input("Enter the path for the output file: ")
    av_api_key = input("Enter your AlienVault OTX API key: ")
    vt_api_key = input("Enter your VirusTotal API key: ")

    public_ips = extract_public_ips_from_pcap(pcap_file_path)

    with open(output_file_path, 'w') as output_file:
        for ip in public_ips:
            av_is_malicious, av_pulses = check_ip_alienvault(ip, av_api_key)
            vt_is_malicious = check_ip_virustotal(ip, vt_api_key)
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

    print(f"Analysis complete. Results are saved in {output_file_path}")

if __name__ == "__main__":
    main()
