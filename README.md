# Encrypted Network Traffic Anomaly Detection 🛡️

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-Machine%20Learning-orange.svg)](https://scikit-learn.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)](https://streamlit.io/)
[![Zeek](https://img.shields.io/badge/Zeek-Network%20Security-black.svg)](https://zeek.org/)

## 📖 Deskripsi Proyek

Repositori ini berisi implementasi Sistem Deteksi Intrusi Jaringan (NIDS) hibrida yang dirancang untuk mendeteksi anomali *zero-day* pada lalu lintas terenkripsi (TLS/HTTPS). Sistem membedah metadata jabat tangan kriptografi menggunakan standar **JA4 Fingerprinting**, sehingga privasi data tetap terjaga murni tanpa melakukan dekripsi *payload*. 

Pendekatan analitik menggunakan algoritma *unsupervised* **Isolation Forest** yang diuji pada lalu lintas data riil. Kinerja pemodelan ini dirancang secara khusus untuk mencegah *alert fatigue* pada analis keamanan, mencapai tingkat **Akurasi 94%** sekaligus menekan **False Positive Rate (FPR) di angka 4%**.

---

## ⚙️ Modul Sistem Utama

Arsitektur kode pada repositori ini dibagi menjadi tiga skrip operasional yang saling terintegrasi:

*   📄 **`pcap_processor.py`** — **Modul Ekstraksi Data**  
    Skrip ini bertugas mengeksekusi file jaringan mentah (`.pcap`) menggunakan mesin Zeek IDS untuk mengekstrak `conn.log` dan `ssl.log`, kemudian menyelaraskannya menjadi fitur dekomposisi JA4 yang terstandarisasi.
*   🧠 **`analyzed_offline.py`** — **Mesin Inferensi Anomali**  
    Skrip ini memuat artefak model *Isolation Forest* dan bobot fitur yang telah dioptimalkan untuk melakukan pemindaian (*scoring*) secara luring terhadap dataset jaringan yang telah diekstrak.
*   📊 **`dashboard_forensik.py`** — **Antarmuka SOC (Security Operations Center)**  
    Memanfaatkan Streamlit untuk merender dasbor visual interaktif yang memfasilitasi proses triase peringatan dini, pemantauan *scatter plot* anomali, dan matriks klasifikasi ancaman.

---

## 🚀 Panduan Penggunaan (*Quick Start*)

### Persyaratan Sistem
Pastikan Anda telah menginstal **Python 3.8+** dan **Zeek IDS** di dalam environment Anda (direkomendasikan menggunakan Linux/Kali Linux).

### Langkah Eksekusi

**Langkah 1: Instalasi Dependensi**
Kloning repositori ini dan instal seluruh pustaka Python yang dibutuhkan.
```bash
git clone [https://github.com/username-anda/nama-repo-anda.git](https://github.com/username-anda/nama-repo-anda.git)
cd nama-repo-anda
pip install -r requirements.txt
