FROM docker.io/python:3.13-slim
RUN pip install --no-cache-dir pyarrow
COPY server.py /app/server.py
WORKDIR /app
EXPOSE 8443
CMD ["python", "server.py"]
