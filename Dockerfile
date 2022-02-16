FROM quay.io/centos/centos:stream9-development

RUN dnf install -y 'dnf-command(builddep)' rpm-build pip git && \
    dnf config-manager --set-enabled crb
RUN pip install rpyc git+https://github.com/pypingou/remote_builder.git

CMD ["remote_builder_server", "--debug"]
