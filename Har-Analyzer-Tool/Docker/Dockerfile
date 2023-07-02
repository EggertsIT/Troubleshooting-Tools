FROM python:3.10
WORKDIR /app
ADD . /app
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS false
RUN pip install --no-cache-dir $DEPENDENCIES
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--browser.serverAddress=127.0.0.1", "--server.enableXsrfProtection=True", "--server.headless=True"]
