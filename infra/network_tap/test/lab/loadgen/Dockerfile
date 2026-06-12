FROM docker.io/python:3.13-slim
RUN pip install --no-cache-dir confluent-kafka requests
COPY loadgen.py /app/loadgen.py
WORKDIR /app
# Idle by default; the driver execs loadgen.py per load tier.
CMD ["sleep", "infinity"]
