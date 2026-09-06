# ==============================================================================
# pcap_processor.py — ZEEK: EKSTRAKSI BEHAVIORAL & JA4 (HARDENED)
# ==============================================================================

import pandas as pd
import os
import subprocess
import shutil

JA4_SCRIPT_PATH = "/home/kali/.zkg/clones/package/ja4/zeek/__load__.zeek"

def check_zeek_available():
    zeek_path = shutil.which('zeek') or shutil.which('bro')
    if not zeek_path:
        print("❌ Zeek tidak ditemukan di sistem.")
        return False
    return True

def process_pcap_with_zeek(pcap_path):
    """Mengekstrak koneksi TLS beserta JA4, SNI, dan Perilaku (Behavioral)."""
    print(f"\n🕵️ Memproses PCAP dengan Zeek: {pcap_path}")

    if not check_zeek_available(): return pd.DataFrame()

    base_dir   = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, "zeek_temp_output")
    if os.path.exists(output_dir): shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    cmd = ["zeek", "-C", "-r", os.path.abspath(pcap_path), f"Log::default_logdir={output_dir}", "policy/tuning/json-logs.zeek"]
    if os.path.exists(JA4_SCRIPT_PATH): cmd.append(JA4_SCRIPT_PATH)

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:
        print(f"❌ Gagal mengeksekusi Zeek: {e}")
        return pd.DataFrame()

    conn_log = os.path.join(output_dir, "conn.log")
    ssl_log  = os.path.join(output_dir, "ssl.log")

    # Validasi eksistensi DAN ukuran file (mencegah file kosong 0 byte)
    if not os.path.exists(ssl_log) or os.path.getsize(ssl_log) == 0:
        print("⚠️ ssl.log tidak terbentuk atau kosong — Tidak ada trafik TLS valid.")
        shutil.rmtree(output_dir, ignore_errors=True)
        return pd.DataFrame()
        
    if not os.path.exists(conn_log) or os.path.getsize(conn_log) == 0:
        print("⚠️ conn.log tidak terbentuk atau kosong.")
        shutil.rmtree(output_dir, ignore_errors=True)
        return pd.DataFrame()

    df_final = pd.DataFrame() # Inisialisasi awal agar tidak error NameError
    
    try:
        # BACA CONN
        df_conn_raw = pd.read_json(conn_log, lines=True)
        
        # Pengaman Kolom CONN (Jika kolom tidak ada, isi dengan default)
        conn_cols_needed = ['uid', 'id.orig_h', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
        for col in conn_cols_needed:
            if col not in df_conn_raw.columns:
                if col in ['duration', 'orig_bytes', 'resp_bytes']: df_conn_raw[col] = 0
                elif col == 'proto': df_conn_raw[col] = 'unknown'
                elif col == 'conn_state': df_conn_raw[col] = 'OTH'
        
        df_conn = df_conn_raw[conn_cols_needed]

        # BACA SSL
        df_ssl_raw = pd.read_json(ssl_log, lines=True)
        df_ssl_raw.columns = [c.lower() for c in df_ssl_raw.columns]

        # Pencarian Kolom Dinamis
        ja4_col = next((c for c in df_ssl_raw.columns if 'ja4' in c and 'ja4s' not in c and '_' not in c.replace('ja4', '')), None)
        ja4s_col = next((c for c in df_ssl_raw.columns if 'ja4s' in c), None)
        sni_col = next((c for c in df_ssl_raw.columns if c in ['server_name', 'ssl.server_name', 'host', 'sni']), None)

        if not ja4_col:
            print("⚠️ Kolom JA4 tidak ditemukan di Zeek output. (Kemungkinan plugin JA4 belum aktif/error)")
            shutil.rmtree(output_dir, ignore_errors=True)
            return pd.DataFrame()

        keep_cols, rename_map = ['uid', ja4_col], {ja4_col: 'JA4'}
        
        if ja4s_col: 
            keep_cols.append(ja4s_col)
            rename_map[ja4s_col] = 'JA4S'
            
        if sni_col:
            keep_cols.append(sni_col)
            rename_map[sni_col] = 'SNI'

        df_ssl = df_ssl_raw[keep_cols].rename(columns=rename_map).drop_duplicates(subset='uid')

        # PENGGABUNGAN (INNER JOIN)
        df_final = pd.merge(df_conn, df_ssl, on='uid', how='inner').rename(columns={
            'id.orig_h': 'src_ip',
            'duration': 'Duration',
            'orig_bytes': 'Orig_Bytes',
            'resp_bytes': 'Resp_Bytes',
            'conn_state': 'Conn_State'
        })

        # PEMBERSIHAN DATA FINAL
        df_final = df_final[~df_final['JA4'].isin(['missing', '-', ''])].reset_index(drop=True)
        if 'SNI' in df_final.columns:
            df_final['SNI'] = df_final['SNI'].fillna('(No SNI)')
        else:
            df_final['SNI'] = '(No SNI)' # Jika kolom SNI benar-benar tidak terbentuk

    except ValueError as ve:
         print(f"❌ Error Nilai/Format JSON: {ve}")
    except Exception as e:
        print(f"❌ Gagal mem-parsing log Zeek: {e}")

    shutil.rmtree(output_dir, ignore_errors=True)
    print(f"✅ Ekstraksi sukses. {len(df_final)} flows TLS utuh ditemukan.")
    
    return df_final