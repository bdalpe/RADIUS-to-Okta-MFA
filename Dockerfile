FROM python:3.11.0a7-alpine3.14

WORKDIR /tmp

ADD requirements.txt ./

RUN pip install -r requirements.txt

ADD okta.py server.py dictionary ./

EXPOSE 1812/udp

CMD ["python", "server.py"]