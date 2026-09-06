# ==============================================================================
# Python_Pcap_Processor.py — MURNI JA4 FINGERPRINTING + SNI EXTRACTION (Scapy)
# ==============================================================================

import pandas as pd
import hashlib
import logging
import uuid
from ipaddress import ip_address

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, TCP, load_layer, conf

conf.checkIPaddr = False
load_layer("tls")

try:
    from scapy.layers.tls.all import TLS, TLSClientHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
except ImportError:
    try:
        from scapy.layers.tls.handshake import TLSClientHello
        TLS_Ext_ServerName = None
    except Exception:
        TLSClientHello = None
        TLS_Ext_ServerName = None

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

def extract_sni(packet):
    try:
        if TLS_Ext_ServerName and packet.haslayer(TLS_Ext_ServerName):
            ext = packet[TLS_Ext_ServerName]
            if hasattr(ext, 'servernames') and ext.servernames:
                sni = ext.servernames[0].servername
                if isinstance(sni, bytes): return sni.decode('utf-8', errors='ignore')
                return str(sni)
        if TLSClientHello and packet.haslayer(TLSClientHello):
            ch = packet[TLSClientHello]
            if hasattr(ch, 'extensions') and ch.extensions:
                for ext in ch.extensions:
                    ext_type = getattr(ext, 'type', getattr(ext, 'val', -1))
                    if int(ext_type) == 0:
                        raw = bytes(ext)
                        if len(raw) > 9:
                            name_len = int.from_bytes(raw[7:9], 'big')
                            return raw[9:9+name_len].decode('utf-8', errors='ignore')
    except Exception: pass
    return '(No SNI)'

def calculate_ja4(packet):
    try:
        if not (TLSClientHello and packet.haslayer(TLSClientHello)): return None
        ch = packet[TLSClientHello]

        version = int(getattr(ch, 'version', 0x0303))
        if version == 0x0304: ver_str = "13"
        elif version == 0x0303: ver_str = "12"
        elif version == 0x0302: ver_str = "11"
        elif version == 0x0301: ver_str = "10"
        else: ver_str = "00"

        raw_ciphers = [int(getattr(c, 'val', c)) for c in getattr(ch, 'ciphers', []) if int(getattr(c, 'val', c)) not in GREASE_VALUES and int(getattr(c, 'val', c)) != 0x0000]
        ciphers_str = ",".join(str(x) for x in sorted(raw_ciphers))
        cipher_hash = hashlib.sha256(ciphers_str.encode()).hexdigest()[:12]

        raw_exts = [int(getattr(ext, 'type', getattr(ext, 'val', 0))) for ext in getattr(ch, 'extensions', []) if int(getattr(ext, 'type', getattr(ext, 'val', 0))) not in GREASE_VALUES]
        exts_str = ",".join(str(x) for x in sorted(raw_exts))
        ext_hash = hashlib.sha256(exts_str.encode()).hexdigest()[:12]

        return f"t{ver_str}d{len(raw_ciphers):02d}{len(raw_exts):02d}_{cipher_hash}_{ext_hash}"
    except Exception: return None

def process_pcap_file(pcap_path):
    print(f"\n🕵️ Memproses PCAP (Scapy) khusus JA4: {pcap_path}")
    
    try: packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"❌ Gagal membaca PCAP: {e}")
        return pd.DataFrame()

    flows = {}
    for pkt in packets:
        if not (IP in pkt and TCP in pkt): continue

        src, dst, sport, dport = pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport
        try: is_orig = ip_address(src) < ip_address(dst) or (ip_address(src) == ip_address(dst) and sport < dport)
        except ValueError: is_orig = src < dst

        key = (src, dst, sport, dport, 'TCP') if is_orig else (dst, src, dport, sport, 'TCP')
        
        if key not in flows:
            flows[key] = {'uid': str(uuid.uuid4())[:8], 'src_ip': src if is_orig else dst, 'ja4': None, 'sni': '(No SNI)'}

        if (is_orig or flows[key]['src_ip'] == src) and len(getattr(pkt[TCP], 'payload', '')) > 5:
            if flows[key]['ja4'] is None:
                ja4_val = calculate_ja4(pkt)
                if ja4_val: flows[key]['ja4'] = ja4_val
                
            if flows[key]['sni'] == '(No SNI)':
                sni_val = extract_sni(pkt)
                if sni_val and sni_val != '(No SNI)': flows[key]['sni'] = sni_val

    data_list = [val for val in flows.values() if val['ja4'] is not None]

    df = pd.DataFrame(data_list)
    
    # Standardisasi penamaan kolom agar sama dengan Zeek
    if not df.empty and 'sni' in df.columns:
        df.rename(columns={'sni': 'SNI'}, inplace=True)
        
    if df.empty: print("⚠️ Tidak ada JA4 yang terekstrak (Tidak ada traffic TLS).")
    else: print(f"✅ Ekstraksi selesai. {len(df)} koneksi ber-JA4 ditemukan.")
    
    return df
