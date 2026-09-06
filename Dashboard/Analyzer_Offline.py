# ==============================================================================
# analyzer_offline.py — HYBRID: L1 (THREAT INTEL) & L2 (ML)
# ==============================================================================

import pandas as pd
import numpy as np
import joblib
import json
import os

# --- KONFIGURASI FILE & ARTIFACTS ---
MODEL_FILE      = 'offline_model_isoforest.pkl'
SCALER_FILE     = 'offline_scaler.pkl'
LE_STATE_FILE   = 'offline_le_state.pkl'
JA4A_FREQ_FILE  = 'offline_ja4a_freq_map.pkl' 
JA4B_FREQ_FILE  = 'offline_ja4b_freq_map.pkl'
JA4C_FREQ_FILE  = 'offline_ja4c_freq_map.pkl'
FEATURES_FILE   = 'offline_features_list.pkl'

JA4_DB_FILE     = 'ja4db.json'
BLACKLIST_FILE  = 'malware-domains.txt' 
ANOMALY_THRESHOLD = 0.55

STATUS_NORMAL       = 'Normal'
STATUS_ANOMALI      = 'ANOMALI (ML)'
STATUS_MALWARE_JA4  = 'MALWARE (JA4DB)'
STATUS_MALWARE_SNI  = 'MALWARE (SNI)'

model         = None
scaler        = None
feature_names = None
le_state      = None
ja4a_freq_map = {}
ja4b_freq_map = {}
ja4c_freq_map = {}
JA4_DATABASE  = {}
SNI_BLACKLIST = set()

def load_artifacts():
    global model, scaler, feature_names, le_state
    global ja4a_freq_map, ja4b_freq_map, ja4c_freq_map
    global JA4_DATABASE, SNI_BLACKLIST

    required = [MODEL_FILE, SCALER_FILE, LE_STATE_FILE, JA4A_FREQ_FILE, 
                JA4B_FREQ_FILE, JA4C_FREQ_FILE, FEATURES_FILE]

    missing = [f for f in required if not os.path.exists(f)]
    if missing:
        print(f"❌ Artifacts tidak ditemukan: {missing}")
        return False

    try:
        model         = joblib.load(MODEL_FILE)
        scaler        = joblib.load(SCALER_FILE)
        le_state      = joblib.load(LE_STATE_FILE)
        ja4a_freq_map = joblib.load(JA4A_FREQ_FILE)
        ja4b_freq_map = joblib.load(JA4B_FREQ_FILE)
        ja4c_freq_map = joblib.load(JA4C_FREQ_FILE)
        feature_names = joblib.load(FEATURES_FILE)
        print(f"✅ Model murni JA4 dimuat | Fitur ML: {len(feature_names)} dimensi")
    except Exception as e:
        print(f"❌ Error memuat model: {e}")
        return False

    # Memuat Lapisan 1: JA4DB & SNI Blacklist
    if os.path.exists(JA4_DB_FILE):
        try:
            with open(JA4_DB_FILE, 'r', encoding='ascii', errors='replace') as f:
                raw_data = json.load(f)
            if isinstance(raw_data, list):
                for item in raw_data:
                    fp = str(item.get('ja4_fingerprint') or item.get('ja4') or '').strip()
                    app = str(item.get('application') or item.get('malware') or 'Unknown').strip()
                    if fp and fp != 'missing' and len(fp) > 10: 
                        JA4_DATABASE[fp] = app
            elif isinstance(raw_data, dict):
                for key, val in raw_data.items():
                    fp = str(key).strip()
                    if fp and fp != 'missing' and len(fp) > 10:
                        JA4_DATABASE[fp] = str(val).strip()
        except Exception as e: pass

    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        SNI_BLACKLIST.add(domain)
        except Exception as e: pass

    return True

load_artifacts()

def preprocess_input(df):
    """SINKRONISASI TOTAL DENGAN JUPYTER (9 DIMENSI)"""
    data = df.copy() 

    # 1. Persiapan Kolom Numerik
    for col in ['Duration', 'Orig_Bytes', 'Resp_Bytes']:
        data[col] = pd.to_numeric(data.get(col, 0), errors='coerce').fillna(0)

    data['JA4']        = data.get('JA4', pd.Series(['missing']*len(data))).fillna('missing').astype(str)
    data['proto']      = data.get('proto', pd.Series(['unknown']*len(data))).fillna('unknown').astype(str)
    data['Conn_State'] = data.get('Conn_State', pd.Series(['OTH']*len(data))).fillna('OTH').astype(str)

    # 2. Dekomposisi JA4
    ja4_parts   = data['JA4'].str.split('_', n=2, expand=True)
    data['JA4_a'] = ja4_parts.get(0, pd.Series(['missing']*len(data))).fillna('missing')
    data['JA4_b'] = ja4_parts.get(1, pd.Series(['missing']*len(data))).fillna('missing')
    data['JA4_c'] = ja4_parts.get(2, pd.Series(['missing']*len(data))).fillna('missing')

    # 3. Log Frequency Encoding
    data['JA4_a_Freq_Log'] = np.log1p(data['JA4_a'].map(ja4a_freq_map).fillna(0))
    data['JA4_b_Freq_Log'] = np.log1p(data['JA4_b'].map(ja4b_freq_map).fillna(0))
    data['JA4_c_Freq_Log'] = np.log1p(data['JA4_c'].map(ja4c_freq_map).fillna(0))

    # 4. Encoding Protokol & Status
    proto_map = {'tcp': 1, 'udp': 0}
    data['Proto_Enc'] = data['proto'].map(proto_map).fillna(2).astype(int)
    data['Conn_State_Enc'] = data['Conn_State'].apply(
        lambda x: le_state.transform([x])[0] if x in le_state.classes_ else -1
    )

    # 5. Fitur Baru: Indikator SNI Hilang (Direct-to-IP)
    data['Is_SNI_Missing'] = data['JA4'].apply(lambda x: 1.0 if str(x)[3:4] == 'i' else 0.0)

    # 6. Log Transform Numerik Perilaku
    data['Log_Duration']   = np.log1p(data['Duration'])
    data['Log_Orig_Bytes'] = np.log1p(data['Orig_Bytes'])
    data['Log_Resp_Bytes'] = np.log1p(data['Resp_Bytes'])

    try:
        X = data[feature_names].astype(float).fillna(0)
    except KeyError as e:
        raise KeyError(f"Missing columns required by model: {e}")
        
    return X

def analyze_pcap_data(dataframe):
    if model is None:
        dataframe['status'], dataframe['anomaly_score'] = 'Error: Model not loaded', 0.0
        return dataframe

    result = dataframe.copy()

    try:
        # =========================================================
        # LAPISAN 2: Eksekusi Machine Learning (Isolation Forest)
        # =========================================================
        X = preprocess_input(result)
        X_scaled = scaler.transform(X)

        # APLIKASI EXTREME WEIGHTING (Sama persis seperti saat training)
        kolom = list(X.columns)
        if 'Is_SNI_Missing' in kolom:
            X_scaled[:, kolom.index('Is_SNI_Missing')] *= 1000.0  
        if 'Conn_State_Enc' in kolom:
            X_scaled[:, kolom.index('Conn_State_Enc')] *= 5.0

        raw_scores     = model.decision_function(X_scaled)
        score_min, score_max = raw_scores.min(), raw_scores.max()
        score_range    = score_max - score_min + 1e-10

        anomaly_scores = 1 - ((raw_scores - score_min) / score_range)
        result['anomaly_score'] = np.round(anomaly_scores, 4)

        result['status'] = result.apply(
            lambda row: STATUS_ANOMALI if row['anomaly_score'] > ANOMALY_THRESHOLD else STATUS_NORMAL, axis=1
        )

        # =========================================================
        # LAPISAN 1: Eksekusi Threat Intelligence (Rule-Based)
        # =========================================================
        if 'JA4' in result.columns and JA4_DATABASE:
            def check_ja4_utuh(x):
                utuh = str(x).strip()
                if utuh in ['', 'missing', '-', 'unknown'] or len(utuh) < 10: return False
                return utuh in JA4_DATABASE
            mask_ja4 = result['JA4'].apply(check_ja4_utuh)
            result.loc[mask_ja4, 'status']        = STATUS_MALWARE_JA4
            result.loc[mask_ja4, 'anomaly_score'] = 1.0 

        if 'SNI' in result.columns and SNI_BLACKLIST:
            def check_sni_utuh(x):
                utuh = str(x).strip().lower()
                if utuh in ['', '(no sni)', 'missing']: return False
                return utuh in SNI_BLACKLIST
            mask_sni = result['SNI'].apply(check_sni_utuh)
            result.loc[mask_sni, 'status']        = STATUS_MALWARE_SNI
            result.loc[mask_sni, 'anomaly_score'] = 1.0 

        # =========================================================
        # PENYUSUNAN IDENTITAS, ALASAN DETEKSI & REKOMENDASI TINDAKAN
        # =========================================================
        def get_identity(row):
            if row['status'] == STATUS_MALWARE_JA4:
                return JA4_DATABASE.get(str(row.get('JA4', '')).strip(), 'Malware JA4DB')
            elif row['status'] == STATUS_MALWARE_SNI:
                return 'Blacklisted Domain'
            else:
                return 'Unknown Device'
                
        result['identity'] = result.apply(get_identity, axis=1)

        def get_reason(row):
            if row['status'] == STATUS_MALWARE_SNI: 
                return f"🛑 Ancaman Terkonfirmasi: SNI '{row.get('SNI', '')}' masuk dalam daftar hitam (Blacklist) C2 Malware global."
            elif row['status'] == STATUS_MALWARE_JA4: 
                return f"🛑 Ancaman Terkonfirmasi: Sidik jari JA4 identik dengan database intelijen ancaman ({row['identity']})."
            elif row['status'] == STATUS_ANOMALI: 
                alasan = f"⚠️ Anomali Statistik (Skor Risiko: {row['anomaly_score']:.2f})."
                if str(row.get('JA4', ''))[3:4] == 'i':
                    alasan += " Trafik Direct-to-IP (menyembunyikan SNI)."
                if row.get('Conn_State') not in ['SF', 'S1']:
                    alasan += f" Status aliran paket tidak wajar ({row.get('Conn_State')})."
                return alasan
            return '✅ Trafik TLS normal dan memiliki struktur wajar.'

        result['alasan_deteksi'] = result.apply(get_reason, axis=1)

        def get_recommendation(row):
            if row['status'] == STATUS_MALWARE_SNI: 
                return f"🔥 TINDAKAN KRITIS: Masukkan domain {row.get('SNI', '')} ke DNS Sinkhole/Firewall. Segera isolasi IP {row.get('src_ip', 'N/A')} dari LAN untuk mencegah penyebaran lateral."
            elif row['status'] == STATUS_MALWARE_JA4: 
                return f"🔥 TINDAKAN KRITIS: Perangkat {row.get('src_ip', 'N/A')} positif terinfeksi {row['identity']}. Putuskan koneksi fisik/WiFi dan lakukan pembersihan Antivirus."
            elif row['status'] == STATUS_ANOMALI: 
                return f"🔍 INVESTIGASI LANJUTAN: Periksa log Endpoint di IP {row.get('src_ip', 'N/A')}. Pastikan apakah ini trafik aplikasi internal kustom, atau aktivitas backdoor tersembunyi. Pantau IP tujuan."
            return "Aman. Tidak ada tindakan diperlukan."

        result['rekomendasi_tindakan'] = result.apply(get_recommendation, axis=1)
        
        return result

    except Exception as e:
        print(f"❌ Error fatal analisis: {e}")
        result['status'], result['anomaly_score'] = f'Error: {str(e)}', 0.0
        return result
