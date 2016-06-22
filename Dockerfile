FROM golang:1.6.0

ENV BROKERPORT 8000
EXPOSE 8000

ENV TIME_ZONE=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TIME_ZONE /etc/localtime && echo $TIME_ZONE > /etc/timezone

#ENV GOPATH=/xxxxx/

RUN apt-get update \
    && apt-get install -y libaio1 pkg-config gcc

COPY . /usr/local/go/src/github.com/asiainfoLDP/datafoundry_servicebroker_go

WORKDIR /usr/local/go/src/github.com/asiainfoLDP/datafoundry_servicebroker_go

#ENV ORACLE_HOME=$(pwd)/oci/12_1
ENV NLS_LANG=AMERICAN_AMERICA.AL32UTF8
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN mkdir -p /usr/local/lib/pkgconfig && cp ./oci/oci8.pc /usr/local/lib/pkgconfig
RUN tar xzvf oci/12_1/liboci.tar.gz -C oci/12_1 \
    && echo $(pwd)/oci/12_1 >> /etc/ld.so.conf \
    && ldconfig

#RUN go get github.com/tools/godep \
#    && godep go build 

RUN go build

CMD ["sh", "-c", "./datafoundry_servicebroker_go"]



