oc login https://lab.asiainfodata.com:8443  -u hehl@asiainfo.com  -p 1857e645-c263-407d-b4e1-e82d15df8d6e --insecure-skip-tls-verify=true

oc new-build https://github.com/asiainfoLDP/datafoundry_servicebroker_go.git

oc run servicebroker-mongo --image=172.30.32.106:5000/datafoundry-servicebroker/datafoundryservicebrokergo \
    --env  ETCDENDPOINT="http://54.222.175.239:2379"  \
    --env  ETCDUSER="asiainfoLDP" \
	--env  ETCDPASSWORD="6ED9BA74-75FD-4D1B-8916-842CB936AC1A" \
    --env  BROKERPORT="8000"  \
    --env  MONGOURL="54.222.175.239:27017"  \
    --env  MONGOADMINUSER="asiainfoLDP"   \
    --env  MONGOADMINPASSWORD="6ED9BA74-75FD-4D1B-8916-842CB936AC1A"   \
    --env  AWS_ACCESS_KEY_ID=AKIAO2SO52RKIE7BCSHA  \
    --env  AWS_SECRET_ACCESS_KEY=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

oc expose  svc servicebroker-mongo