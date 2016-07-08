package handler

import (
	_ "database/sql"
	//"fmt"
	_ "github.com/mattn/go-oci8"
	"github.com/pivotal-cf/brokerapi"
	"strings"
	_ "fmt"
	"errors"
	
	_ "github.com/asiainfoLDP/datafoundry_servicebroker_go/handler/odc_daas_rest"
)



func (handler *Oracle_Handler_Dedicated) DoProvision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, ServiceInfo, error) {
	return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, errors.New("not implemented")
}

func (handler *Oracle_Handler_Dedicated) DoLastOperation(myServiceInfo *ServiceInfo) (brokerapi.LastOperation, error) {
	//因为是同步模式，协议里面并没有说怎么处理啊，统一反馈成功吧！
	return brokerapi.LastOperation{
		State:       brokerapi.Succeeded,
		Description: "It's a sync method!",
	}, nil
}

func (handler *Oracle_Handler_Dedicated) DoDeprovision(myServiceInfo *ServiceInfo, asyncAllowed bool) (brokerapi.IsAsync, error) {
	return brokerapi.IsAsync(false), errors.New("not implemented")
}

func (handler *Oracle_Handler_Dedicated) DoBind(myServiceInfo *ServiceInfo, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, Credentials, error) {
	
	mycredentials := Credentials{
		//Uri:      "oracle://" + newusername + ":" + newpassword + "@" + myServiceInfo.Url + "/" + myServiceInfo.Database,
		Uri:      OracleConnString(myServiceInfo.Database, myServiceInfo.Password, handler.adress, handler.sid),
		Hostname: strings.Split(handler.adress, ":")[0],
		Port:     strings.Split(handler.adress, ":")[1],
		Username: myServiceInfo.User,
		Password: myServiceInfo.Password,
		Name:     myServiceInfo.Database,
	}
	
	

	myBinding := brokerapi.Binding{Credentials: mycredentials}

	return myBinding, mycredentials, errors.New("not implemented")

}

func (handler *Oracle_Handler_Dedicated) DoUnbind(myServiceInfo *ServiceInfo, mycredentials *Credentials) error {

	return nil

}

//=====================================================================

type Oracle_Handler_Dedicated struct {
	name string
	
	adminUser     string
	adminPassword string
	adress        string
	sid           string
	dashboard     string
	
	connString string
}

func newOracleHandler_Dedicated(name string) *Oracle_Handler_Dedicated {
	return &Oracle_Handler_Dedicated {
		name: name,
	}
}

func (oh *Oracle_Handler_Dedicated) setEnvNames(envAaminuser, envAdminPassword, envAddress, envSID, envDashboard string) *Oracle_Handler_Dedicated {
	
	oh.adminUser = getenv(envAaminuser)         //共享实例和独立实例的管理员用户名
	oh.adminPassword = getenv(envAdminPassword) //共享实例和独立实例的管理员密码
	oh.adress = getenv(envAddress)              //共享实例和独立实例的地址
	oh.sid = getenv(envSID)                     //共享实例和独立实例的system id
	oh.dashboard = getenv(envDashboard)         //dashboard地址
	
	if len(oh.dashboard) < 3 {
		oh.dashboard = ""
	}
	
	oh.connString = OracleConnString(oh.adminUser, oh.adminPassword, oh.adress, oh.sid)
	
	return oh
}

func (oh *Oracle_Handler_Dedicated) register() *Oracle_Handler_Dedicated {
	register("Oracle_" + oh.name, oh)
	return oh
}

//=====================================================================

func init() {
	newOracleHandler_Dedicated("Dedicated").
		register().
		setEnvNames(
			"ORACLEADMINUSER_DEDICATED", 
			"ORACLEADMINPASSWORD_DEDICATED", 
			"ORACLEADDRESS_DEDICATED", 
			"ORACLESID_DEDICATED", 
			"ORACLEDASHBOARD_DEDICATED",
		)
		
}

// https://docs.oracle.com/cloud/latest/dbcs_dbaas/CSDBR/op-paas-service-dbcs-api-v1.1-instances-%7BidentityDomainId%7D-post.html
