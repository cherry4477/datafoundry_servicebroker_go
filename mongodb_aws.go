package main

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/etcd/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/coreos/etcd/client"
	"github.com/mitchellh/mapstructure"
	"github.com/pivotal-cf/brokerapi"
	"github.com/pivotal-golang/lager"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type myServiceBroker struct {
	ProvisionDetails   brokerapi.ProvisionDetails
	UpdateDetails      brokerapi.UpdateDetails
	DeprovisionDetails brokerapi.DeprovisionDetails

	ProvisionedInstanceIDs   []string
	DeprovisionedInstanceIDs []string
	UpdatedInstanceIDs       []string

	BoundInstanceIDs    []string
	BoundBindingIDs     []string
	BoundBindingDetails brokerapi.BindDetails
	SyslogDrainURL      string

	UnbindingDetails brokerapi.UnbindDetails

	InstanceLimit int

	ProvisionError     error
	BindError          error
	DeprovisionError   error
	LastOperationError error
	UpdateError        error

	BrokerCalled             bool
	LastOperationState       brokerapi.LastOperationState
	LastOperationDescription string

	AsyncAllowed bool

	ShouldReturnAsync brokerapi.IsAsync
	DashboardURL      string
}

func (myBroker *myServiceBroker) Services() []brokerapi.Service {
	// Return a []brokerapi.Service here, describing your service(s) and plan(s)
	//myBroker.BrokerCalled = true
	myServices := []brokerapi.Service{}
	myService := brokerapi.Service{}
	//获取catalog信息
	resp, err := etcdapi.Get(context.Background(), "/servicebroker/"+"mongodb_aws"+"/catalog", &client.GetOptions{Recursive: true})
	if err != nil {
		logger.Error("Can not get catalog information from etcd", err)
	} else {
		logger.Debug("Successful get catalog information from etcd. NodeInfo is " + resp.Node.Key)
	}

	//fmt.Printf("%#v", resp.Node)
	for _, nodeSvc := range resp.Node.Nodes {
		svc := make(map[string]interface{})
		for _, v := range nodeSvc.Nodes {
			key := strings.TrimPrefix(v.Key, nodeSvc.Key+"/")
			svc[key] = v.Value
			fmt.Println(key, v.Value)
			switch key {
			case "Bindable", "PlanUpdatable":
				svc[key], _ = strconv.ParseBool(v.Value)
			case "tags":
				tags := []string{}
				json.Unmarshal([]byte(v.Value), &tags)
				svc[key] = tags
			case "metadata":
				metadata := brokerapi.ServiceMetadata{}
				json.Unmarshal([]byte(v.Value), &metadata)
				svc[key] = metadata
			default:
				svc[key] = v.Value
			}
		}

		fmt.Println(svc)
		if err := mapstructure.Decode(svc, &myService); err != nil {
			fmt.Println("Decode error!", err)
		} else {
			myServices = append(myServices, myService)
		}
		/*
			if j, err := json.Marshal(svc); err == nil {
				//fmt.Println(string(j))
				if err = json.Unmarshal(j, &myService); err != nil {
					fmt.Println(err)
				} else {
					fmt.Println("+++++++", myService)
					myServices = append(myServices, myService)
				}
			}
		*/
	}

	return myServices

}

func (myBroker *myServiceBroker) Provision(
	instanceID string,
	details brokerapi.ProvisionDetails,
	asyncAllowed bool,
) (brokerapi.ProvisionedServiceSpec, error) {
	// Provision a new instance here. If async is allowed, the broker can still
	// chose to provision the instance synchronously.
	myBroker.BrokerCalled = true

	if myBroker.ProvisionError != nil {
		return brokerapi.ProvisionedServiceSpec{}, myBroker.ProvisionError
	}

	/*
	   //暂不实现对实例数量的控制
	   if len(myBroker.ProvisionedInstanceIDs) >= myBroker.InstanceLimit {
	       return brokerapi.ProvisionedServiceSpec{}, brokerapi.ErrInstanceLimitMet
	   }
	*/

	if sliceContains(instanceID, myBroker.ProvisionedInstanceIDs) {
		return brokerapi.ProvisionedServiceSpec{}, brokerapi.ErrInstanceAlreadyExists
	}

	myBroker.ProvisionDetails = details
	myBroker.ProvisionedInstanceIDs = append(myBroker.ProvisionedInstanceIDs, instanceID)
	return brokerapi.ProvisionedServiceSpec{DashboardURL: myBroker.DashboardURL}, nil
}

func (myBroker *myServiceBroker) LastOperation(instanceID string) (brokerapi.LastOperation, error) {
	// If the broker provisions asynchronously, the Cloud Controller will poll this endpoint
	// for the status of the provisioning operation.
	// This also applies to deprovisioning (work in progress).
	if myBroker.LastOperationError != nil {
		return brokerapi.LastOperation{}, myBroker.LastOperationError
	}

	return brokerapi.LastOperation{State: myBroker.LastOperationState, Description: myBroker.LastOperationDescription}, nil
}

func (myBroker *myServiceBroker) Deprovision(instanceID string, details brokerapi.DeprovisionDetails, asyncAllowed bool) (brokerapi.IsAsync, error) {
	// Deprovision a new instance here. If async is allowed, the broker can still
	// chose to deprovision the instance synchronously, hence the first return value.
	myBroker.BrokerCalled = true

	if myBroker.DeprovisionError != nil {
		return brokerapi.IsAsync(false), myBroker.DeprovisionError
	}

	myBroker.DeprovisionDetails = details
	myBroker.DeprovisionedInstanceIDs = append(myBroker.DeprovisionedInstanceIDs, instanceID)

	if sliceContains(instanceID, myBroker.ProvisionedInstanceIDs) {
		return brokerapi.IsAsync(false), nil
	}
	return brokerapi.IsAsync(false), brokerapi.ErrInstanceDoesNotExist
}

func (myBroker *myServiceBroker) Bind(instanceID, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, error) {
	// Bind to instances here
	// Return a binding which contains a credentials object that can be marshalled to JSON,
	// and (optionally) a syslog drain URL.
	myBroker.BrokerCalled = true

	if myBroker.BindError != nil {
		return brokerapi.Binding{}, myBroker.BindError
	}

	myBroker.BoundBindingDetails = details

	myBroker.BoundInstanceIDs = append(myBroker.BoundInstanceIDs, instanceID)
	myBroker.BoundBindingIDs = append(myBroker.BoundBindingIDs, bindingID)

	return brokerapi.Binding{
		Credentials: myCredentials{
			Host:     "127.0.0.1",
			Port:     3000,
			Username: "batman",
			Password: "robin",
		},
		SyslogDrainURL: myBroker.SyslogDrainURL,
	}, nil
}

func (myBroker *myServiceBroker) Unbind(instanceID, bindingID string, details brokerapi.UnbindDetails) error {
	// Unbind from instances here
	myBroker.BrokerCalled = true

	myBroker.UnbindingDetails = details

	if sliceContains(instanceID, myBroker.ProvisionedInstanceIDs) {
		if sliceContains(bindingID, myBroker.BoundBindingIDs) {
			return nil
		}
		return brokerapi.ErrBindingDoesNotExist
	}

	return brokerapi.ErrInstanceDoesNotExist
}

func (myBroker *myServiceBroker) Update(instanceID string, details brokerapi.UpdateDetails, asyncAllowed bool) (brokerapi.IsAsync, error) {
	// Update instance here
	myBroker.BrokerCalled = true

	if myBroker.UpdateError != nil {
		return false, myBroker.UpdateError
	}

	myBroker.UpdateDetails = details
	myBroker.UpdatedInstanceIDs = append(myBroker.UpdatedInstanceIDs, instanceID)
	myBroker.AsyncAllowed = asyncAllowed
	return myBroker.ShouldReturnAsync, nil
}

type myCredentials struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func sliceContains(needle string, haystack []string) bool {
	for _, element := range haystack {
		if element == needle {
			return true
		}
	}
	return false
}

//定义日志和etcd的全局变量
var logger lager.Logger
var etcdapi client.KeysAPI

//定义工具函数
func etcdget(key string) (*client.Response, error) {
	resp, err := etcdapi.Get(context.Background(), key, nil)
	if err != nil {
		logger.Error("Can not get "+key+" from etcd", err)
	} else {
		logger.Debug("Successful get " + key + " from etcd. value is " + resp.Node.Value)
	}
	return resp, err
}

func main() {
	//初始化参数，参数应该从环境变量中获取
	var username, password string
	//todo参数应该改为从环境变量中获取

	//初始化日志对象，日志输出到stdout
	logger = lager.NewLogger("mongodb_aws")                          //替换为环境变量
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.DEBUG)) //默认日志级别

	//初始化etcd客户端
	cfg := client.Config{
		Endpoints: []string{"http://localhost:2379"}, //替换为环境变量
		Transport: client.DefaultTransport,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}
	c, err := client.New(cfg)
	if err != nil {
		logger.Error("Can not init ectd client", err)
	}
	etcdapi = client.NewKeysAPI(c)

	//初始化serviceborker对象
	serviceBroker := &myServiceBroker{}

	//取得用户名和密码
	resp, err := etcdget("/servicebroker/" + "mongodb_aws" + "/username") //需要修改为环境变量参数
	if err != nil {
		logger.Error("Can not init username,Progrom Exit!", err)
		os.Exit(1)
	} else {
		username = resp.Node.Value
	}

	resp, err = etcdget("/servicebroker/" + "mongodb_aws" + "/password") //需要修改为环境变量参数
	if err != nil {
		logger.Error("Can not init password,Progrom Exit!", err)
		os.Exit(1)
	} else {
		password = resp.Node.Value
	}

	//装配用户名和密码
	credentials := brokerapi.BrokerCredentials{
		Username: username,
		Password: password,
	}

	fmt.Println("start http server")
	brokerAPI := brokerapi.New(serviceBroker, logger, credentials)
	http.Handle("/", brokerAPI)
	http.ListenAndServe(":8000", nil) //需要修改为环境变量
}
