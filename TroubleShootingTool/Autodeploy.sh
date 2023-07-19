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


def parse_har_file(har_dict, blocking_time_threshold):
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

        is_blocking = any(url.endswith(ext) for ext in ('.js', '.css')) or (time_ms > blocking_time_threshold)

        if is_blocking:
            blocking_resources.append([url, method, status, mime_type, size_bytes, time_ms])

        request_domain = urlparse(url).netloc
        if request_domain != first_request_domain:
            third_party_resources.append([url, method, status, mime_type, size_bytes, time_ms])

        data.append([url, method, status, mime_type, size_bytes, time_ms])

    return data, blocking_resources, third_party_resources



def analyze_har_file(filename, case_id, blocking_time_threshold):
    har_dict = load_har_file(filename)
    data, blocking_resources, third_party_resources = parse_har_file(har_dict, blocking_time_threshold)

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
    blocking_time_threshold = st.slider("Blocking Time Threshold", min_value=0, max_value=1000, value=100, step=10)

    if har_file is not None and analyze_button:
        with tempfile.NamedTemporaryFile(suffix=".har", delete=True) as tmp:
            tmp.write(har_file.getvalue())
            tmp.flush()      
            df, error_df, blocking_df, third_party_df, zip_data = analyze_har_file(tmp.name, case_id, blocking_time_threshold)
        st.success("HAR file analysis completed.")

        st.header("DataFrames")
        st.subheader("All Requests")
        st.write(df)

        expander = st.expander("See explanation for error codes")
        expander.write("""

            - 400 Bad Request: This code is used when the server cannot understand the request due to malformed syntax or invalid parameters.
                It is often caused by errors in the client's input or request structure.

            - 401 Unauthorized: This status code is sent when authentication is required, and the client has not provided valid credentials or has not authenticated successfully.
                It indicates that the requested resource requires authentication to access.

            - 403 Forbidden: The server understands the request and the client is authenticated, but the client does not have sufficient permissions to access the requested resource.
                This status code is often used for access control purposes.

            - 404 Not Found: This is one of the most well-known status codes. It indicates that the requested resource could not be found on the server.
                It is typically returned when the URL or URI provided in the request does not match any existing resource.

            - 405 Method Not Allowed: This code is used when the client attempts to use an HTTP method that is not allowed for the requested resource.
                For example, if a resource only allows GET requests and the client sends a POST request, the server may respond with a 405 status code.

            - 408 Request Timeout: This code is sent when the server did not receive a complete request from the client within the time it was willing to wait.
                It indicates that the server has timed out waiting for the client to send the necessary data.

            - 429 Too Many Requests: This status code is returned when the client has sent too many requests in a given amount of time.
                It is often used to prevent abuse or to enforce rate limiting on APIs.
            """)

        
        st.subheader("Error Requests")
        st.write(error_df)

        expander = st.expander("See explanation for Blocking Resources")
        expander.write("""
It will apply to any(url.endswith(ext) for ext in ('.js', '.css')) or (time_ms > blocking_time_threshold)
            """)
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


def extract_rst_details_from_pcap(pcap_file, case_id, display_filter='tcp.flags.reset == 1'):
    rst_details = []
    cap = pyshark.FileCapture(str(pcap_file), display_filter=display_filter)  # Convert to string
    for pkt in cap:
        try:
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            rst_details.append({
                'Source_IP': ip_src,
                'Destination_IP': ip_dst,
                'Timestamp': pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S')
            })
        except AttributeError:
            pass
    cap.close()
    df = pd.DataFrame(rst_details)
    consolidated_df = df.groupby(['Source_IP', 'Destination_IP']).size().reset_index(name='Number_of_RSTs')

    return df, consolidated_df


def rst_analysis():
    hide_menu_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        </style>
    """
    st.markdown(hide_menu_style, unsafe_allow_html=True)
    st.markdown("""
    ## How To:

    Identifying Connection Issues: A TCP RST packet is sent by a host to tear down a connection immediately.
    It may indicate a host or application that's having trouble maintaining stable connections.

    Troubleshooting: The termination of a TCP sessions might be an indication of an application error or Block.
    
    Correlate what you find here with what you find in the Client Handshake analysis to get a clue what might cause the problem.
    
    """)
    uploaded_file = st.file_uploader("1. Select PCAP File", type=["pcap", "pcapng"])
    case_id = st.text_input("2. Enter Case ID")

    if st.button("3. TCP RST Details"):
        if uploaded_file and case_id:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:  
                tmp.write(uploaded_file.getvalue())
                tmp.close()

                pcap_file = Path(tmp.name)
                df, consolidated_df = extract_rst_details_from_pcap(pcap_file, case_id, 'tcp.flags.reset == 1')
                st.write(df)
                st.write(consolidated_df)

                with BytesIO() as zip_buffer:
                    with ZipFile(zip_buffer, 'w') as zip_file:
                        zip_file.writestr('rst_details.csv', df.to_csv(index=False))
                        zip_file.writestr('consolidated_rst_details.csv', consolidated_df.to_csv(index=False))

                    st.download_button(
                        label="Download Results",
                        data=zip_buffer.getvalue(),
                        file_name=case_id + '_rst.zip',
                        mime='application/zip'
                    )

                pcap_file.unlink()
                st.stop()

def extract_retransmissions_from_pcap(pcap_file, case_id, display_filter='tcp.analysis.retransmission'):
    retransmission_details = []
    cap = pyshark.FileCapture(str(pcap_file), display_filter=display_filter)  # Convert to string
    for pkt in cap:
        try:
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            retransmission_details.append({
                'Source_IP': ip_src,
                'Destination_IP': ip_dst,
                'Timestamp': pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S')
            })
        except AttributeError:
            pass
    cap.close()
    df = pd.DataFrame(retransmission_details)
    return df



def retransmission_analysis():
    hide_menu_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        </style>
    """
    st.markdown(hide_menu_style, unsafe_allow_html=True)
    uploaded_file = st.file_uploader("1. Select PCAP File", type=["pcap", "pcapng"])
    case_id = st.text_input("2. Enter Case ID")

    if st.button("3. TCP Retransmission Details"):
        if uploaded_file and case_id:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:  
                tmp.write(uploaded_file.getvalue())
                tmp.close()

                pcap_file = Path(tmp.name)
                df = extract_retransmissions_from_pcap(pcap_file, case_id, 'tcp.analysis.retransmission')
                st.write(df)

                with BytesIO() as zip_buffer:
                    with ZipFile(zip_buffer, 'w') as zip_file:
                        zip_file.writestr('retransmission_details.csv', df.to_csv(index=False))

                    st.download_button(
                        label="Download Results",
                        data=zip_buffer.getvalue(),
                        file_name=case_id + '_retransmissions.zip',
                        mime='application/zip'
                    )

                pcap_file.unlink()
                st.stop()

def main():
    st.sidebar.title("Navigation")
    st.config.set_option('server.maxUploadSize', 1024)

    page = st.sidebar.radio("Go to", ["SSL Handshake Analysis", "HAR File Analysis", "TCP RST Analysis", "TCP Retransmission Analysis", "Impressum"])
    
    if page == "SSL Handshake Analysis":
        pcap_analysis()
    elif page == "HAR File Analysis":
        har_analysis()
    elif page == "TCP RST Analysis":
        rst_analysis()
    elif page == "TCP Retransmission Analysis":
        retransmission_analysis()
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
RUN echo '-----BEGIN CERTIFICATE-----
MIIE0zCCA7ugAwIBAgIJANu+mC2Jt3uTMA0GCSqGSIb3DQEBCwUAMIGhMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTERMA8GA1UEBxMIU2FuIEpvc2Ux
FTATBgNVBAoTDFpzY2FsZXIgSW5jLjEVMBMGA1UECxMMWnNjYWxlciBJbmMuMRgw
FgYDVQQDEw9ac2NhbGVyIFJvb3QgQ0ExIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRA
enNjYWxlci5jb20wHhcNMTQxMjE5MDAyNzU1WhcNNDIwNTA2MDAyNzU1WjCBoTEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExETAPBgNVBAcTCFNhbiBK
b3NlMRUwEwYDVQQKEwxac2NhbGVyIEluYy4xFTATBgNVBAsTDFpzY2FsZXIgSW5j
LjEYMBYGA1UEAxMPWnNjYWxlciBSb290IENBMSIwIAYJKoZIhvcNAQkBFhNzdXBw
b3J0QHpzY2FsZXIuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
qT7STSxZRTgEFFf6doHajSc1vk5jmzmM6BWuOo044EsaTc9eVEV/HjH/1DWzZtcr
fTj+ni205apMTlKBW3UYR+lyLHQ9FoZiDXYXK8poKSV5+Tm0Vls/5Kb8mkhVVqv7
LgYEmvEY7HPY+i1nEGZCa46ZXCOohJ0mBEtB9JVlpDIO+nN0hUMAYYdZ1KZWCMNf
5J/aTZiShsorN2A38iSOhdd+mcRM4iNL3gsLu99XhKnRqKoHeH83lVdfu1XBeoQz
z5V6gA3kbRvhDwoIlTBeMa5l4yRdJAfdpkbFzqiwSgNdhbxTHnYYorDzKfr2rEFM
dsMU0DHdeAZf711+1CunuQIDAQABo4IBCjCCAQYwHQYDVR0OBBYEFLm33UrNww4M
hp1d3+wcBGnFTpjfMIHWBgNVHSMEgc4wgcuAFLm33UrNww4Mhp1d3+wcBGnFTpjf
oYGnpIGkMIGhMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTERMA8G
A1UEBxMIU2FuIEpvc2UxFTATBgNVBAoTDFpzY2FsZXIgSW5jLjEVMBMGA1UECxMM
WnNjYWxlciBJbmMuMRgwFgYDVQQDEw9ac2NhbGVyIFJvb3QgQ0ExIjAgBgkqhkiG
9w0BCQEWE3N1cHBvcnRAenNjYWxlci5jb22CCQDbvpgtibd7kzAMBgNVHRMEBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAw0NdJh8w3NsJu4KHuVZUrmZgIohnTm0j+
RTmYQ9IKA/pvxAcA6K1i/LO+Bt+tCX+C0yxqB8qzuo+4vAzoY5JEBhyhBhf1uK+P
/WVWFZN/+hTgpSbZgzUEnWQG2gOVd24msex+0Sr7hyr9vn6OueH+jj+vCMiAm5+u
kd7lLvJsBu3AO3jGWVLyPkS3i6Gf+rwAp1OsRrv3WnbkYcFf9xjuaf4z0hRCrLN2
xFNjavxrHmsH8jPHVvgc1VD0Opja0l/BRVauTrUaoW6tE+wFG5rEcPGS80jjHK4S
pB5iDj2mUZH1T8lzYtuZy0ZPirxmtsk3135+CKNa2OCAhhFjE0xd
-----END CERTIFICATE-----' > /usr/local/share/ca-certificates/ZscalerRootCertificate-2048-SHA256.pem && chmod 644 /usr/local/share/ca-certificates/ZscalerRootCertificate-2048-SHA256.pem && pip install -trusted-host files.pythonhosted.org pip_system_certs && apt update && apt -y install tshark && pip install streamlit pandas pyshark config && apt update && apt -y install && rm -rf /var/lib/apt/lists/*
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS false
EXPOSE 8501
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1
USER appuser
ENTRYPOINT ["streamlit", "run", "app.py", "--browser.serverAddress=127.0.0.1", "--server.enableXsrfProtection=True", "--server.headless=True"]

EOF

docker build -t troubleshooting-tool .
docker run -p 127.0.0.1:8501:8501 troubleshooting-tool
