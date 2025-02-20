from scapy.all import sniff, IP, TCP, UDP
def packet_callback(packet):
    if IP in packet:  # لو الباكيت فيها بيانات IP
        src_ip = packet[IP].src  # عنوان المصدر
        dst_ip = packet[IP].dst  # عنوان الوجهة
        protocol = "OTHER"
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport  # بورت المصدر
            dst_port = packet[TCP].dport  # بورت الوجهة
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port, dst_port = "N/A", "N/A"

        print(f"[{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
# تشغيل الـ Sniffer مع إعدادات متقدمة
sniff(prn=packet_callback, iface="Wi-Fi", count=10,filter="tcp", store=False) 
