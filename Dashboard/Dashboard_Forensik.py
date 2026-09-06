# ==============================================================================
# Dashboard_Forensik.py — ENTERPRISE SOC EDITION (HYBRID ETA)
# ==============================================================================

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import platform
import os
import time

try:
    from analyzer_offline import (
        analyze_pcap_data, STATUS_NORMAL, STATUS_ANOMALI, 
        STATUS_MALWARE_JA4, STATUS_MALWARE_SNI
    )
except ImportError as e:
    st.error(f"❌ SISTEM BERHENTI: Modul core analyzer tidak ditemukan -> {e}")
    st.stop()

current_os = platform.system()
try:
    if current_os == 'Windows':
        import Python_Pcap_Processor as pcap_processor
        PROCESSOR_INFO = "Scapy Engine (Windows Core)"
    else:
        import pcap_processor
        PROCESSOR_INFO = "Zeek NIDS Engine (Unix Core)"
except ImportError as e:
    st.error(f"❌ SISTEM BERHENTI: Ekstraktor PCAP tidak ditemukan -> {e}")
    st.stop()

# --- 1. KONFIGURASI HALAMAN ---
st.set_page_config(
    page_title="Analisis Jaringan Terenkripsi", 
    layout="wide", 
    page_icon="👁️‍🗨️",
    initial_sidebar_state="expanded"
)

# --- 2. INJEKSI CSS ENTERPRISE ---
st.markdown("""
    <style>
    /* Styling for metric cards */
    div[data-testid="metric-container"] {
        background-color: #1E1E2E;
        border: 1px solid #333344;
        padding: 5% 5% 5% 10%;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    div[data-testid="metric-container"] > label {
        color: #A0A0B0 !important;
        font-weight: 600 !important;
        letter-spacing: 1px;
        font-size: 0.9rem;
    }
    /* Main Title Styling */
    .soc-title {
        text-align: center;
        font-family: 'Courier New', Courier, monospace;
        color: #00F0FF;
        text-shadow: 0px 0px 10px rgba(0, 240, 255, 0.5);
        margin-bottom: 0px;
    }
    .soc-subtitle {
        text-align: center;
        color: #888899;
        font-size: 1.1rem;
        margin-top: -10px;
        margin-bottom: 30px;
        letter-spacing: 2px;
    }
    </style>
""", unsafe_allow_html=True)

COLOR_MAP = {
    STATUS_NORMAL      : '#00F0FF',   # Cyan / Biru Neon
    STATUS_ANOMALI     : '#FFB300',   # Amber / Oranye
    STATUS_MALWARE_JA4 : '#FF003C',   # Merah Neon 
    STATUS_MALWARE_SNI : '#B000FF',   # Ungu Neon
}

def normalize_columns(df):
    df.columns = [c.strip().lower() for c in df.columns]
    rename_map = {'ja4': 'JA4', 'ja4_fingerprint': 'JA4', 'ja4s': 'JA4S', 'sni': 'SNI', 'server_name': 'SNI'}
    df.rename(columns=rename_map, inplace=True)
    return df

def compute_confusion_matrix(df_result, label_file):
    try:
        df_label = pd.read_csv(label_file)
        if 'label' not in df_label.columns: return None, "Kolom label tidak ditemukan."
        if len(df_label) != len(df_result):
            if 'uid' in df_result.columns and 'uid' in df_label.columns:
                df_label = pd.merge(df_result[['uid']], df_label, on='uid', how='left').fillna(0)
            else: return None, f"Ketidaksesuaian panjang data: {len(df_label)} vs {len(df_result)}."
        y_true = df_label['label'].values
        y_pred = [1 if s in [STATUS_MALWARE_JA4, STATUS_MALWARE_SNI, STATUS_ANOMALI] else 0 for s in df_result['status']]
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(y_true, y_pred)
        TN, FP, FN, TP = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        DR        = TP / (TP + FN) if (TP + FN) > 0 else 0
        FPR       = FP / (FP + TN) if (FP + TN) > 0 else 0
        Precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        F1        = (2 * Precision * DR) / (Precision + DR) if (Precision + DR) > 0 else 0
        return {'TP': int(TP), 'TN': int(TN), 'FP': int(FP), 'FN': int(FN),
                'DR': DR, 'FPR': FPR, 'Precision': Precision, 'F1': F1, 'Acc': (TP+TN)/(TP+TN+FP+FN)}, None
    except Exception as e: return None, str(e)


# --- 3. HEADER & JUDUL UTAMA ---
st.markdown("<h1 class='soc-title'>⎈ ANALISIS JARINGAN ENKRIPSI</h1>", unsafe_allow_html=True)
st.markdown("<p class='soc-subtitle'>DETEKSI ANOMALI LALU LINTAS JARINGAN TERENKRIPSI MENGGUNAKAN ALGORITMA ISOLATION FOREST BERBASIS JA4 FINGERPRINTING</p>", unsafe_allow_html=True)

# --- 4. PANEL KONTROL SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Panel Kontrol SOC")
    st.markdown("---")
    st.markdown("**Pemasukan Data (Ingestion)**")
    uploaded_file  = st.file_uploader("Unggah Telemetri Jaringan (PCAP/CSV)", type=["csv", "pcap", "pcapng"])
    
    st.markdown("---")
    st.markdown("**Parameter Mesin ML**")
    threshold_val  = st.slider("Sensitivitas Anomali (Threshold)", 0.30, 0.90, 0.55, 0.05)
    
    st.markdown("---")
    st.caption(f"**Sistem Backend:** {PROCESSOR_INFO}")
    st.caption("**Lapisan 1:** Intelijen Ancaman Berbasis Aturan (Rule-Based)")
    st.caption("**Lapisan 2:** Machine Learning Unsupervised (Isolation Forest)")

# --- 5. LOGIKA EKSEKUSI UTAMA ---
if uploaded_file:
    temp_pcap = f"temp_{uploaded_file.name}"
    with open(temp_pcap, "wb") as f: f.write(uploaded_file.getbuffer())

    temp_label = None # Label dinonaktifkan di sidebar sesuai kode asal
    
    df_raw = None
    try:
        if uploaded_file.name.endswith(('.pcap', '.pcapng')):
            with st.spinner('📡 Mencegat Paket & Mengekstrak Sidik Jari Kriptografi...'):
                if current_os == 'Windows': df_raw = pcap_processor.process_pcap_file(temp_pcap)
                else: df_raw = pcap_processor.process_pcap_with_zeek(temp_pcap)
            if df_raw is None or len(df_raw) == 0:
                st.error("❌ TRAFIK TLS TIDAK DITEMUKAN. PEMASUKAN DATA DIBATALKAN.")
                st.stop()
        else:
            df_raw = normalize_columns(pd.read_csv(temp_pcap))
            if len(df_raw.columns) < 2: df_raw = normalize_columns(pd.read_csv(temp_pcap, sep='\t'))

        if 'JA4' in df_raw.columns:
            df_raw = df_raw[~df_raw['JA4'].isin(['missing', 'unknown', '-', np.nan])].reset_index(drop=True)
            
        if df_raw.empty or 'JA4' not in df_raw.columns:
            st.error("❌ FORMAT DATA TIDAK VALID: Sidik Jari Kriptografi (JA4) Tidak Ditemukan.")
            st.stop()

        st.success(f"✅ PEMASUKAN DATA BERHASIL: {len(df_raw):,} sesi terenkripsi berhasil ditangkap.")

        if st.button("🚀 MULAI ANALISIS HIBRIDA", use_container_width=True):
            with st.spinner('Menjalankan Intelijen Ancaman & AI Perilaku...'):
                time.sleep(1.5) # Simulasi loading untuk efek enterprise
                df_result = analyze_pcap_data(df_raw)

            # --- 6. INDIKATOR KINERJA UTAMA (KPI) ---
            st.markdown("### 📊 POSTUR KEAMANAN (KPI)")
            c1, c2, c3, c4 = st.columns(4)
            total_traffic = len(df_result)
            normal_traffic = (df_result['status'] == STATUS_NORMAL).sum()
            anomali_ml = (df_result['status'] == STATUS_ANOMALI).sum()
            threat_intel = (df_result['status'] == STATUS_MALWARE_JA4).sum() + (df_result['status'] == STATUS_MALWARE_SNI).sum()

            c1.metric("Total Sesi TLS", f"{total_traffic:,}")
            c2.metric("Trafik Aman (L2)", f"{normal_traffic:,}", f"{(normal_traffic/total_traffic)*100:.1f}%", delta_color="normal")
            c3.metric("Anomali Perilaku (L2)", f"{anomali_ml:,}", f"{(anomali_ml/total_traffic)*100:.1f}%", delta_color="inverse")
            c4.metric("Ancaman Terkonfirmasi (L1)", f"{threat_intel:,}", "Kritis", delta_color="inverse")
            
            st.markdown("<br>", unsafe_allow_html=True)

            # --- 7. TABEL KERJA (SOC WORKSPACE) ---
            tab1, tab2, tab3, tab4 = st.tabs([
                "🌐 Lanskap Ancaman", 
                "🚨 Triase & Respons SOC", 
                "🧬 Telemetri ML", 
                "📈 Diagnostik Sistem"
            ])

            # TAB 1: LANSKAP ANCAMAN (Grafik)
            with tab1:
                st.markdown("#### Distribusi Lalu Lintas Terenkripsi")
                fig_col1, fig_col2 = st.columns([1, 2])
                
                with fig_col1:
                    # Grafik Donat untuk Kesehatan Jaringan
                    status_counts = df_result['status'].value_counts().reset_index()
                    status_counts.columns = ['Status', 'Jumlah']
                    fig_donut = px.pie(status_counts, values='Jumlah', names='Status', hole=0.7,
                                       color='Status', color_discrete_map=COLOR_MAP,
                                       template="plotly_dark")
                    fig_donut.update_layout(margin=dict(t=0, b=0, l=0, r=0), showlegend=False)
                    st.plotly_chart(fig_donut, use_container_width=True)

                with fig_col2:
                    # Histogram Skor Anomali
                    fig_hist = px.histogram(df_result, x='anomaly_score', color='status',
                                            color_discrete_map=COLOR_MAP, nbins=50,
                                            template="plotly_dark")
                    fig_hist.add_vline(x=threshold_val, line_dash='dash', line_color='#FF003C', annotation_text=f"Ambang Batas ({threshold_val})")
                    fig_hist.update_layout(xaxis_title="Skor Probabilitas Anomali", yaxis_title="Jumlah Sesi", margin=dict(t=10, b=0, l=0, r=0))
                    st.plotly_chart(fig_hist, use_container_width=True)

            # TAB 2: TRIASE & RESPONS SOC (Dataframe & SOP)
            with tab2:
                st.markdown("#### Intelijen yang Dapat Ditindaklanjuti & Respons Insiden")
                risk_df = df_result[df_result['status'] != STATUS_NORMAL].copy()
                
                if risk_df.empty: 
                    st.success("✅ TIDAK ADA ANCAMAN TERDETEKSI. JARINGAN AMAN.")
                else:
                    # Sorot baris kritis
                    def color_soc_rows(row):
                        if row['status'] in [STATUS_MALWARE_SNI, STATUS_MALWARE_JA4]: return ['background-color: rgba(255, 0, 60, 0.2)'] * len(row)
                        elif row['status'] == STATUS_ANOMALI: return ['background-color: rgba(255, 179, 0, 0.2)'] * len(row)
                        return [''] * len(row)
                    
                    display_cols = ['src_ip', 'status', 'identity', 'anomaly_score', 'alasan_deteksi', 'rekomendasi_tindakan', 'JA4', 'SNI']
                    st.dataframe(risk_df[display_cols].style.apply(color_soc_rows, axis=1), use_container_width=True, height=350)
                    
                    st.download_button("📥 EKSPOR LAPORAN INSIDEN (CSV)", risk_df.to_csv(index=False).encode('utf-8'), "laporan_insiden_soc.csv", "text/csv")

            # TAB 3: TELEMETRI ML (Analisis Mendalam)
            with tab3:
                st.markdown("#### Analisis Sidik Jari Kriptografi (Target Teratas)")
                if risk_df.empty: st.info("Tidak ada telemetri anomali yang tersedia.")
                else:
                    ja4_counts = risk_df['JA4'].value_counts().head(10).reset_index()
                    ja4_counts.columns = ['Sidik Jari JA4', 'Jumlah Hit']
                    fig_bar = px.bar(ja4_counts, x='Jumlah Hit', y='Sidik Jari JA4', orientation='h',
                                     template="plotly_dark", color='Jumlah Hit', color_continuous_scale='Reds')
                    fig_bar.update_layout(yaxis={'categoryorder':'total ascending'})
                    st.plotly_chart(fig_bar, use_container_width=True)

            # TAB 4: DIAGNOSTIK SISTEM (Evaluasi Model)
            with tab4:
                st.markdown("#### Validasi Kunci Jawaban (Ground Truth) Model AI")
                if temp_label and os.path.exists(temp_label):
                    metrics, err = compute_confusion_matrix(df_result, temp_label)
                    if err: st.error(err)
                    else:
                        m1, m2, m3, m4 = st.columns(4)
                        m1.metric("Recall (Tingkat Deteksi)", f"{metrics['DR']*100:.2f}%")
                        m2.metric("Presisi", f"{metrics['Precision']*100:.2f}%")
                        m3.metric("Skor F1", f"{metrics['F1']*100:.2f}%")
                        m4.metric("Total Akurasi", f"{metrics['Acc']*100:.2f}%")
                        st.caption(f"**Confusion Matrix:** True Positive ({metrics['TP']}) | True Negative ({metrics['TN']}) | False Positive ({metrics['FP']}) | False Negative ({metrics['FN']})")
                else: st.info("ℹ️ Unggah file Label Kunci Jawaban (Ground Truth) di bilah samping untuk menjalankan diagnostik model.")

    except Exception as e:
        st.error(f"❌ KEGAGALAN SISTEM KRITIS: {e}")
    finally:
        for tmp in [temp_pcap, temp_label]:
            if tmp and os.path.exists(tmp): os.remove(tmp)
else:
    st.info("Sistem Siap Menunggu File Jaringan Yang Dianalisis (Upload PCAP/CSV diSamping).")
