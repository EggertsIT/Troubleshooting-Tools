#!/bin/bash
mkdir ./Docker_Build_har_analyzer
cd ./Docker_Build_har_analyzer

# Define your application's dependencies
DEPENDENCIES=" pandas streamlit"

# Create the Python script
cat > app.py << EOF
import os
import shutil
import json
import pandas as pd
import streamlit as st
from urllib.parse import urlparse
import subprocess
import platform
import zipfile
from io import BytesIO
import base64

# Rest of the code...


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

        # Check for blocking resources
        is_blocking = any(url.endswith(ext) for ext in ('.js', '.css'))
        if is_blocking:
            blocking_resources.append([url, method, status, mime_type, size_bytes, time_ms])

        # Check for third-party resources
        request_domain = urlparse(url).netloc
        if request_domain != first_request_domain:
            third_party_resources.append([url, method, status, mime_type, size_bytes, time_ms])

        data.append([url, method, status, mime_type, size_bytes, time_ms])

    return data, blocking_resources, third_party_resources

def analyze_data(data):
    total_size = sum(entry[4] for entry in data)
    average_size = total_size / len(data)
    return average_size

def filter_errors(data):
    errors = [entry for entry in data if 400 <= entry[2] < 600]
    return errors

def inspect_headers(har_dict):
    headers_str = ''
    for entry in har_dict['log']['entries']:
        request = entry['request']
        response = entry['response']

        url = request['url']
        request_headers = request['headers']
        response_headers = response['headers']

        headers_str += f"URL: {url}\n"
        headers_str += "Request Headers:\n"
        for header in request_headers:
            headers_str += f"{header['name']}: {header['value']}\n"

        headers_str += "Response Headers:\n"
        for header in response_headers:
            headers_str += f"{header['name']}: {header['value']}\n"

        headers_str += '\n'

    return headers_str

def analyze_har_file(filename, case_id):
    har_dict = load_har_file(filename)
    data, blocking_resources, third_party_resources = parse_har_file(har_dict)
    average_size = analyze_data(data)

    df = pd.DataFrame(data, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])
    error_data = filter_errors(data)
    error_df = pd.DataFrame(error_data, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])
    blocking_df = pd.DataFrame(blocking_resources, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])
    third_party_df = pd.DataFrame(third_party_resources, columns=['URL', 'Method', 'Status', 'MIME Type', 'Size (bytes)', 'Time (ms)'])

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zipf:
        zipf.writestr('all_requests.csv', df.to_csv(index=False))
        zipf.writestr('error_requests.csv', error_df.to_csv(index=False))
        zipf.writestr('blocking_resources.csv', blocking_df.to_csv(index=False))
        zipf.writestr('third_party_resources.csv', third_party_df.to_csv(index=False))
        zipf.writestr('headers.txt', inspect_headers(har_dict))

    return df, error_df, blocking_df, third_party_df, zip_buffer.getvalue()

def app():
    st.title("HAR Analyzer v0.1")
    hide_menu_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        </style>
        """
    st.markdown(hide_menu_style, unsafe_allow_html=True)

    st.text("Select a HAR file and enter a case ID to analyze.")

    har_file = st.file_uploader("1. Select HAR File", type=['har'])
    case_id = st.text_input("2. Enter Case ID")
    analyze_button = st.button("3. Analyze HAR File")

    if har_file is not None and analyze_button:
        har_filename = 'temp.har'  # Use a temporary file name
        with open(har_filename, "wb") as f:
            f.write(har_file.getvalue())
        
        df, error_df, blocking_df, third_party_df, zip_data = analyze_har_file(har_filename, case_id)
        os.remove(har_filename)
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

if __name__ == "__main__":
    app()

EOF

# Create a Dockerfile
cat > Dockerfile << EOF
# Use an official Python runtime as a parent image
FROM python:3.10

# Set the working directory in the container to /app
WORKDIR /app

# Add the current directory contents into the container at /app
ADD . /app

ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS false

# Install any needed packages
RUN pip install --no-cache-dir $DEPENDENCIES

# Make port 8502 available to the world outside this container
EXPOSE 8502

# Run app.py when the container launches
CMD ["streamlit", "run", "app.py", "--browser.serverAddress=127.0.0.1", "--server.enableXsrfProtection=True", "--server.headless=True"]
EOF

# Build the Docker image
docker build -t har_analyzer .

# Run the Docker container
docker run -p 127.0.0.1:8501:8501 har_analyzer
