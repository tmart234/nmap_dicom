FROM python:3.10-slim

WORKDIR /app

RUN pip install --no-cache-dir pynetdicom

COPY pynetdicom_echo_scp.py .

EXPOSE 11114

# Set PYTHONUNBUFFERED so print statements appear in logs immediately
ENV PYTHONUNBUFFERED=1

CMD ["python", "pynetdicom_echo_scp.py"]