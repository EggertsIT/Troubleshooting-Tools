#!/bin/bash

mkdir ./Docker_Build_handshake_analyzer
cd ./Docker_Build_handshake_analyzer
DEPENDENCIES="pyshark pandas streamlit"

cat > app.py << EOF
import pyshark
import pandas as pd
import streamlit as st
from zipfile import ZipFile
from io import BytesIO
from pathlib import Path
import tempfile

def extract_traffic_details_from_pcap(pcap_file, case_id, display_filter='tls.handshake.type == 1'):
    traffic_details = []
    cap = pyshark.FileCapture(str(pcap_file), display_filter=display_filter)  # Convert to string
    for pkt in cap:
        try:
            sni = pkt.tls.handshake_extensions_server_name
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            traffic_details.append({
                'SNI': sni,
                'Ingress_Source_IP': ip_src,
                'Ingress_Destination_IP': ip_dst,
                'Timestamp': pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S')
            })
        except AttributeError:
            pass
    cap.close()
    df = pd.DataFrame(traffic_details)

    consolidated_df = df.groupby('SNI').agg({
        'Ingress_Source_IP': 'nunique',
        'Ingress_Destination_IP': 'nunique',
        'Timestamp': 'count'
    }).reset_index()
    consolidated_df.columns = ['SNI', 'Unique_Ingress_Sources', 'Unique_Ingress_Destinations', 'Packet_Count']

    return df, consolidated_df

def main():
    st.title("ClientHello Analyzer v0.1")
    
    hide_menu_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        </style>
        """
    st.markdown(hide_menu_style, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("1. Select PCAP File", type=["pcap", "pcapng"])
    case_id = st.text_input("2. Enter Case ID")

    if st.button("3. SSL Traffic Details"):
        if uploaded_file and case_id:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:  
                tmp.write(uploaded_file.getvalue())
                tmp.close()  # Close the temporary file

                pcap_file = Path(tmp.name)  
                df, consolidated_df = extract_traffic_details_from_pcap(pcap_file, case_id, 'tls.handshake.type == 1')
                st.write(df)
                st.write(consolidated_df)

                # Create a ZipFile in memory
                with BytesIO() as zip_buffer:
                    with ZipFile(zip_buffer, 'w') as zip_file:
                        zip_file.writestr('traffic_details.csv', df.to_csv(index=False))
                        zip_file.writestr('consolidated_traffic_details.csv', consolidated_df.to_csv(index=False))

                    # Download the ZIP file
                    st.download_button(
                        label="Download Results",
                        data=zip_buffer.getvalue(),
                        file_name=case_id + '.zip',
                        mime='application/zip'
                    )

                # Clean up the temporary file
                pcap_file.unlink()
                st.stop()

if __name__ == "__main__":
    main()
EOF

cat > Dockerfile << EOF
FROM python:3.9
WORKDIR /app
ADD . /app
RUN apt-get update && apt-get install -y tshark
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS false
RUN pip install --no-cache-dir $DEPENDENCIES
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--browser.serverAddress=127.0.0.1", "--server.enableXsrfProtection=True", "--server.headless=True"]

EOF

docker build -t ssl_analyzer .
docker run -p 127.0.0.1:8501:8501 ssl_analyzer
