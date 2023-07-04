#!/bin/bash
docker version > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "Error: Docker is not installed or running. Please install and start Docker, then try again."
    exit 1
fi

mkdir ./Docker_Build_troubleshooting
cd ./Docker_Build_troubleshooting

cat > app.py << EOF
import os
import json
import pandas as pd
import streamlit as st
from urllib.parse import urlparse
import pyshark
from zipfile import ZipFile
from pathlib import Path
import tempfile
from io import BytesIO

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


def load_har_file(filename):
    with open(filename, 'r') as f:
        har_dict = json.load(f)
    return har_dict


def parse_har_file(har_dict):
    data = []
    blocking_resources = []
    third_party_resources = []

    first_request_domain = urlparse(har_dict['log']['entries'][0]['request']['url']).netloc

    for entry in har_dict['log']['entries']:
        url = entry['request']['url']
        method = entry['request']['method']
        status = entry['response']['status']
        mime_type = entry['response']['content']['mimeType']
        size_bytes = entry['response']['bodySize']
        time_ms = entry['time']

        is_blocking = any(url.endswith(ext) for ext in ('.js', '.css'))
        if is_blocking:
            blocking_resources.append([url, method, status, mime_type, size_bytes, time_ms])

        request_domain = urlparse(url).netloc
        if request_domain != first_request_domain:
            third_party_resources.append([url, method, status, mime_type, size_bytes, time_ms])

        data.append([url, method, status, mime_type, size_bytes, time_ms])

    return data, blocking_resources, third_party_resources


def analyze_har_file(filename, case_id):
    har_dict = load_har_file(filename)
    data, blocking_resources, third_party_resources = parse_har_file(har_dict)

    df = pd.DataFrame(data, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])
    error_data = [entry for entry in data if 400 <= entry[2] < 600]
    error_df = pd.DataFrame(error_data, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])
    blocking_df = pd.DataFrame(blocking_resources, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])
    third_party_df = pd.DataFrame(third_party_resources, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])

    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, 'w') as zipf:
        zipf.writestr('all_requests.csv', df.to_csv(index=False))
        zipf.writestr('error_requests.csv', error_df.to_csv(index=False))
        zipf.writestr('blocking_resources.csv', blocking_df.to_csv(index=False))
        zipf.writestr('third_party_resources.csv', third_party_df.to_csv(index=False))

    return df, error_df, blocking_df, third_party_df, zip_buffer.getvalue()


def pcap_analysis():
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
                tmp.close()

                pcap_file = Path(tmp.name)
                df, consolidated_df = extract_traffic_details_from_pcap(pcap_file, case_id, 'tls.handshake.type == 1')
                st.write(df)
                st.write(consolidated_df)

                with BytesIO() as zip_buffer:
                    with ZipFile(zip_buffer, 'w') as zip_file:
                        zip_file.writestr('traffic_details.csv', df.to_csv(index=False))
                        zip_file.writestr('consolidated_traffic_details.csv', consolidated_df.to_csv(index=False))

                    st.download_button(
                        label="Download Results",
                        data=zip_buffer.getvalue(),
                        file_name=case_id + '.zip',
                        mime='application/zip'
                    )

                pcap_file.unlink()

                st.stop()
            
    


def har_analysis():
    har_file = st.file_uploader("1. Select HAR File", type=['har'])
    case_id = st.text_input("2. Enter Case ID")
    analyze_button = st.button("3. Analyze HAR File")
    hide_menu_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        </style>
    """
    st.markdown(hide_menu_style, unsafe_allow_html=True)
    if har_file is not None and analyze_button:
        with tempfile.NamedTemporaryFile(suffix=".har", delete=True) as tmp:
            tmp.write(har_file.getvalue())
            tmp.flush()      
            df, error_df, blocking_df, third_party_df, zip_data = analyze_har_file(tmp.name, case_id)
        st.success("HAR file analysis completed.")

        st.header("DataFrames")
        st.subheader("All Requests")
        st.write(df)

        st.subheader("Error Requests")
        st.write(error_df)

        st.subheader("Blocking Resources")
        st.write(blocking_df)

        st.subheader("Third-Party Resources")
        st.write(third_party_df)

        st.download_button(
            label="Download Results",
            data=zip_data,
            file_name=f"{case_id}.zip",
            mime='application/zip'
        )

    

def impressum():
        hide_menu_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
        """
        st.markdown(hide_menu_style, unsafe_allow_html=True)
        st.header("Report a Bug")
        st.markdown("""# Troubleshooting-Tools

### in case you find a Bug please report with screenshot to bug@eggerts.it    

## Please read this disclaimer carefully before using or relying on this Software.

1.    No Support: The software and code provided are offered on an "as is" basis, without any support or warranty of any kind, either expressed or implied. The maintainers and contributors of this sofware do not provide any guarantee regarding the functionality, reliability, or suitability of the software for any particular purpose.

2.    Use at Your Own Risk: Any use of the software, code, or information provided in this repository is at your own risk. The maintainers and contributors shall not be held liable for any damages, losses, or issues arising from the use of the software, including but not limited to any direct, indirect, incidental, or consequential damages.

3.    No Responsibility: The maintainers and contributors of this repository disclaim any responsibility for the accuracy, completeness, or quality of the software or code provided. They make no assurances that the software will be error-free, secure, or compatible with your requirements.

4.    Independent Evaluation: It is your responsibility to independently evaluate the suitability and functionality of the software for your intended use. You should thoroughly review and test the code before incorporating it into your own projects.

5.    No Endorsement: The presence of any specific software, code, or third-party resources in this repository does not imply an endorsement or recommendation by the maintainers or contributors. Any third-party resources referenced or linked in this repository are provided for informational purposes only.

6.    No Legal Advice: The information provided by this sotware is not intended to constitute legal advice. If you have legal concerns or questions regarding the use or licensing of the software, you should consult with a qualified legal professional.

### By using or relying on the software, code, or information provided, you agree to accept all risks and responsibilities associated with such use. If you do not agree with this disclaimer, you should refrain from using or relying on any materials provided here.

### Please note that this disclaimer may be subject to change without notice. It is your responsibility to regularly check for updates or modifications to this disclaimer.
### --> https://github.com/EggertsIT/Troubleshooting-Tools <--
### Full Sourcecode also avilable here.


## This software is build with:

- os
- json
- pandas
- streamlit
- urlparse from urllib.parse
- pyshark
- ZipFile from zipfile 
- Path from pathlib
- tempfile
- BytesIO from io 

this list is not guaranteed to be complete.


""")


def main():
    st.sidebar.title("Navigation")
    st.config.set_option('server.maxUploadSize', 1024)

    page = st.sidebar.radio("Go to", ["SSL Handshake Analysis", "HAR File Analysis", "Impressum"])
    
    if page == "SSL Handshake Analysis":
        pcap_analysis()
    elif page == "HAR File Analysis":
        har_analysis()
    elif page == "Impressum":
        impressum()


if __name__ == "__main__":
    main()

EOF

# Create a Dockerfile
cat > Dockerfile << EOF
FROM python:3.9-slim
WORKDIR /app
RUN useradd -m appuser && chown -R appuser:appuser /app
ADD . /app
RUN apt-get update && apt-get -y install tshark \
    && pip install streamlit pandas pyshark \
    && apt-get update && apt-get -y install && rm -rf /var/lib/apt/lists/*
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS false
EXPOSE 8501
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1
USER appuser
ENTRYPOINT ["streamlit", "run", "app.py", "--browser.serverAddress=127.0.0.1", "--server.enableXsrfProtection=True", "--server.headless=True"]

EOF

docker build -t troubleshooting-tool .
docker run -p 127.0.0.1:8501:8501 troubleshooting-tool

