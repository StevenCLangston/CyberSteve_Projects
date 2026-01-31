from scapy.all import *

def process_packet(packet):
    src_ip = packet(IP).src
    dst_ip = packet(IP).dst
    src_port = packet(TCP).sport
    dst_port = packet(TCP).dport

print(f"[HTTP?] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

if packet.haslayer(Raw):
    print("  [+] Payload detected!")
    
#Looking for GET request keyword in the plain text
if payload.startswith("GET"):
   src_ip = packet(IP).src
   dst_ip = packet(IP).dst
   
   print(f"\n[+] HTTP GET Request from {src_ip} to {dst_ip}")
   
   #Find host and path using regex
   host = re.search(r"Host: (.*?\r\n", payload)
   path = re.search(r"GET (.*?) HTTP", payload)
   
   if host and path:
      host = host.group(1)
      path + path.group(1)
      print(f"  [+] Request for: http://{host}{path}")
      
   #Check for User-Agent
   user_agent = re.search(r"User-Agent: (.*?)\r\n", payload)
   if user_agent:
      print(f"  [+] User-Agent: {user_agent.group(1)}")
      

            
#Main sniffing loop
BPF_FILTER = "tcp and port 80"
print(f"Starting HTTP sniffer (filter: '{BPF_FILTER}')... Press Ctrl+C to stop.")

sniff(store=0, prn=process_packet, filter=BPF_FILTER)
