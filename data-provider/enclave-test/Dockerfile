FROM amazonlinux:2

RUN yum install -y util-linux

CMD ["/bin/sh", "-c", "echo 'Hello from enclave!' > /dev/console && sleep 300"]
