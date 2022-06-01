FROM python:latest
COPY . /app
WORKDIR /app
RUN ["bash", "install_script.sh"]
ENTRYPOINT ["bash", "exec_script.sh"]
