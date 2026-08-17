FROM docker:26-cli
RUN apk add --no-cache python3 git
RUN git config --system --add safe.directory /opt/sentinel
COPY server.py /server.py
COPY deploy.sh /deploy.sh
RUN chmod +x /deploy.sh
CMD ["python3", "/server.py"]
