import streamlit as st
import sqlite3
import pandas as pd

st.set_page_config(
    page_title="OSINT Threat Intelligence Portal",
    page_icon="🛡️",
    layout="wide"
)

DB_PATH = "data/iocs.db"

@st.cache_data(ttl=60)
def load_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT ioc_type, value, sources_list as sources, source_count, risk_score, timestamp, description FROM iocs", conn)
    conn.close()
    return df

st.title("🛡️ OSINT Threat Intelligence Portal")
st.markdown("Canlı Təhdid Indikatorları (IOC) İdarəetmə və Endirmə Paneli")

try:
    df = load_data()
    
    # Yuxarı Statistika Kartları
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Toplam IOC Sayı", len(df))
    col2.metric("IP Indikatorları", len(df[df['ioc_type'] == 'ip']))
    col3.metric("URL Indikatorları", len(df[df['ioc_type'] == 'url']))
    col4.metric("Yüksək Riskli (Score ≥ 60)", len(df[df['risk_score'] >= 60]))

    st.divider()

    # Süzgəc (Filter) bölməsi
    st.sidebar.header("🔍 Süzgəc və Axtarış")
    selected_types = st.sidebar.multiselect("IOC Növü", df['ioc_type'].unique(), default=df['ioc_type'].unique())
    min_score = st.sidebar.slider("Minimum Risk Skoru", 0, 100, 30, 10)
    search_query = st.sidebar.text_input("Axtarış (IP, URL, Domain, Hash)")

    # Dataların filtrlənməsi
    filtered_df = df[(df['ioc_type'].isin(selected_types)) & (df['risk_score'] >= min_score)]
    if search_query:
        filtered_df = filtered_df[filtered_df['value'].str.contains(search_query, case=False, na=False)]

    st.subheader(f"Nəticələr ({len(filtered_df)} indikator tapıldı)")

    # Eksport Düymələri
    col_csv, col_json = st.columns(2)
    with col_csv:
        csv_data = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Filtrlənmiş CSV-ni Endir", data=csv_data, file_name="osint_iocs.csv", mime="text/csv")
    with col_json:
        json_data = filtered_df.to_json(orient="records", indent=4).encode('utf-8')
        st.download_button("📥 Filtrlənmiş JSON-u Endir", data=json_data, file_name="osint_iocs.json", mime="application/json")

    # Cədvəl
    st.dataframe(filtered_df, use_container_width=True, height=500)

except Exception as e:
    st.error(f"Məlumatlar yüklənərkən xəta baş verdi: {e}")
