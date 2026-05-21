FROM docker:26-cli
RUN apk add --no-cache python3 git
COPY server.py /server.py
COPY deploy.sh /deploy.sh
RUN chmod +x /deploy.sh
CMD ["python3", "/server.py"]
