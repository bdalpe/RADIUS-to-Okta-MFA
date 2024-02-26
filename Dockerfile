FROM python:3.11-alpine3.19

WORKDIR /tmp

ADD requirements.txt ./

RUN pip install -r requirements.txt

ADD okta.py server.py dictionary ./

EXPOSE 1812/udp

CMD ["python", "server.py"]