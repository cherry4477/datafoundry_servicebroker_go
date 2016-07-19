package handler

import (
	_ "database/sql"
	//_ "github.com/mattn/go-oci8"
	"github.com/pivotal-cf/brokerapi"
	"strings"
	"errors"
	"fmt"
	"time"
	
	oraclecloudrest "github.com/asiainfoLDP/datafoundry_servicebroker_go/handler/oracle_cloud_rest"
)

const DevMode = true

func init() {
	/*
	go func() {
		<- time.After(5 * time.Second)
		(&Oracle_Dedicated_Handler{
			level:   "PAAS",
			edition: "EE",
			shape:   "oc3",
			usableStorage: "50",
		}).DoProvision("",  brokerapi.ProvisionDetails{}, true)
	}()
	*/
	
	//go ViewJobStatus(
	// 	"https://dbaas.oraclecloud.com:443/paas/service/dbcs/api/v1.1/instances/aibdx/status/create/job/5745893",
	// 	"svc-db-om4rydqhaoaua", "system", "eN9WZWlJdTQ##g3nCEqyU9p3")
	
}
func ViewJobStatus(jobUrl, serviceName, adminUser, adminPassword string) {
	//<- time.After(3 * time.Minute)	
	
	for {
		println("================================================================")
		var jobStatus oraclecloudrest.JobStatusInfo
		res, err := oracleDaasClient.ViewJobStatus("create", jobUrl, &jobStatus)
		if err != nil {
			fmt.Println("ViewJobStatus:", err.Error())
		}
		fmt.Println("ViewJobStatus result:", jobStatus)
		fmt.Println("ViewJobStatus response:", res)
		fmt.Println()
		
		if strings.ToLower(jobStatus.Status) == "running" {
			break
		}
		
		<- time.After(2 * time.Minute)
	}
	
	for {
		<- time.After(time.Minute)
		
		println("###############################################################")
		var instanceServerInfos []oraclecloudrest.InstanceServerInfo
		_, err := oracleDaasClient.ViewDatabaseInstanceServers (serviceName, &instanceServerInfos)
		if err != nil {
			fmt.Println("ViewDatabaseInstanceServers:", err.Error())
			continue
		}
		if len(instanceServerInfos) == 0 {
			fmt.Println("ViewDatabaseInstanceServers: no servers found")
			continue
		}
		
		instanceServer := &instanceServerInfos[0]
		
		if strings.ToLower(instanceServer.Status) != "running" {
			fmt.Println("ViewDatabaseInstanceServers: server not running")
			continue
		}
		fmt.Println("instanceServer =", instanceServer)
		
		connectDesc := instanceServer.ConnectDescriptor
		connString := OracleConnString2(adminUser, adminPassword, connectDesc)
		fmt.Println("connectDesc =", connectDesc)
		fmt.Println("connString =", connString)
		
		
		err = tryTestDbUsibility(connString)
		if err != nil {
			fmt.Println("tryTestDbUsibility error:", err.Error())
		}
		
		break
	}
}

func tryTestDbUsibility(connString string) error {
	fmt.Println("start tryTestDbUsibility:", connString)
	
	newdbname, newusername, _, err := CreateOracleDbAndUser(connString, "2G", true)
	if err != nil {
		fmt.Println("ViewJobStatus, CreateOracleDbAndUser:", err.Error())
		return err
	}
	fmt.Println("ViewJobStatus, CreateOracleDbAndUser succeeded. newdbname = ", newdbname, ", newusername=", newusername)
	
	for range [5]struct{}{} {
		err = DeleteOracleDbAndUser(connString, newdbname, newusername)
		if err != nil {
			fmt.Println("ViewJobStatus, CreateOracleDbAndUser:", err.Error())
			return err
		}
		
		fmt.Println("ViewJobStatus, DeleteOracleDbAndUser succeeded.")
		
		break
	}
	
	return nil
}

//===================================================================
// 
//===================================================================

// 大概需要25分钟创建完成。
func (handler *Oracle_Dedicated_Handler) DoProvision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, ServiceInfo, error) {
	privateKeyText, vmPublicKeyText, err :=  oraclecloudrest.GenerateRsaPair()
	if err != nil {
		println("GenerateRsaPair:", err.Error())
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}
	
	serviceName := "svc-db-" + oraclecloudrest.NewThirteenLengthID()
	
	adminUsername := "system"
	adminPassword := ""
	
	var config *oraclecloudrest.OracleDaasCreateConfig
	if handler.level == "BASIC" {
		config = oraclecloudrest.NewOracleDaasCreateConfig_Basic(serviceName, handler.edition, handler.shape, vmPublicKeyText)
	} else {
		adminPassword = oraclecloudrest.NewPassword8_30()
		usableStorage := handler.usableStorage // GB
		config = oraclecloudrest.NewOracleDaasCreateConfig_PaaS(serviceName, handler.edition, handler.shape, vmPublicKeyText, adminPassword, usableStorage)
	}
	
	go func() {
		res, err := oracleDaasClient.CreateDatabaseInstance(config)
		if err != nil {
			println("CreateDatabaseInstance:", err.Error())
			return
		}
		
		jobUrl := res.Header.Get("Location")
		
		fmt.Println("jobUrl =", jobUrl)
		if handler.level == "PAAS" {
			go ViewJobStatus(jobUrl, serviceName, adminUsername, adminPassword) // for testing only
		}
	}()
	
	myServiceInfo := ServiceInfo{
		//Url:            jobUrl,
		Admin_user:     adminUsername, // "root",
		Admin_password: adminPassword,
		Database:       serviceName,
		User:           privateKeyText,
		//Password:       newpassword,
	}
	
	provsiondetail := brokerapi.ProvisionedServiceSpec{DashboardURL: "", IsAsync: true}

	return provsiondetail, myServiceInfo, nil
}

func (handler *Oracle_Dedicated_Handler) DoLastOperation(myServiceInfo *ServiceInfo) (brokerapi.LastOperation, error) {
	serviceName := myServiceInfo.Database
	
	var instanceInfo oraclecloudrest.InstanceInfo
	_, err := oracleDaasClient.ViewDatabaseInstance (serviceName, &instanceInfo)
	if err != nil {
		fmt.Println("ViewDatabaseInstance:", err.Error())
		
		return brokerapi.LastOperation{
			State:       brokerapi.InProgress,
			Description: "In progress.",
		}, err
	}
	
	if strings.ToLower(instanceInfo.Status) == "running" {
		return brokerapi.LastOperation{
			State:       brokerapi.Succeeded,
			Description: "Succeeded!",
		}, nil
	} else {
		return brokerapi.LastOperation{
			State:       brokerapi.InProgress,
			Description: "In progress.",
		}, nil
	}
}

func (handler *Oracle_Dedicated_Handler) DoDeprovision(myServiceInfo *ServiceInfo, asyncAllowed bool) (brokerapi.IsAsync, error) {
	serviceName := myServiceInfo.Database
	
	for range [3]struct{}{} {
		res, err := oracleDaasClient.DeleteDatabaseInstance (serviceName)
		if err != nil {
			return brokerapi.IsAsync(false), err
		} else {
			jobId := res.Header.Get("Location")
			//go func () {
				_ = jobId
			//}()
			
			break
		}
	}
	
	return brokerapi.IsAsync(false), nil
}

func (handler *Oracle_Dedicated_Handler) DoBind(myServiceInfo *ServiceInfo, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, Credentials, error) {
	serviceName := myServiceInfo.Database
	
	var instanceServerInfos []oraclecloudrest.InstanceServerInfo
	_, err := oracleDaasClient.ViewDatabaseInstanceServers (serviceName, &instanceServerInfos)
	if err != nil {
		fmt.Println("ViewDatabaseInstanceServers:", err.Error())
		return brokerapi.Binding{}, Credentials{}, err
	}
	if len(instanceServerInfos) == 0 {
		return brokerapi.Binding{}, Credentials{}, errors.New("no servers found")
	}
	
	instanceServer := &instanceServerInfos[0]
	
	if strings.ToLower(instanceServer.Status) != "running" {
		return brokerapi.Binding{}, Credentials{}, errors.New("server not running")
	}
	
	host := instanceServer.ReservedIP
	
	var mycredentials *Credentials
	if handler.level == "BASIC" {
		mycredentials = &Credentials{
			Uri:      `Please save *username* env as a private key file and use *ssh -i key opc@host* to login.`,
			Hostname: host,               // ssh host
			//Port:     port,               // ssh port
			//Name:     myServiceInfo.User, 
			Username: myServiceInfo.User, // ssh privateKeyText
			//Password: myServiceInfo.Password,
		}
	} else { // "PAAS"
		port := instanceServer.ListenerPort
		//sid := instanceServer.SID
		connectDesc := instanceServer.ConnectDescriptor
		
		uri := OracleConnString2(
				myServiceInfo.Admin_user, 
				myServiceInfo.Admin_password, 
				connectDesc)
		
		mycredentials = &Credentials{
			Uri:      uri,                          // db connection uri
			Hostname: host,                         // ssh host
			Port:     fmt.Sprintf("%d", port),      // ssh port
			//Name:     myServiceInfo.User,           // ssh privateKeyText
			Username: myServiceInfo.Admin_user,     // db root
			Password: myServiceInfo.Admin_password, // db root password
		}
		
		if DevMode {
			go tryTestDbUsibility(uri)
		}
	}

	myBinding := brokerapi.Binding{Credentials: *mycredentials}

	return myBinding, *mycredentials, nil

}

func (handler *Oracle_Dedicated_Handler) DoUnbind(myServiceInfo *ServiceInfo, mycredentials *Credentials) error {

	return nil

}

//=====================================================================
// 
//=====================================================================

type Oracle_Dedicated_Handler struct {
	level         string
	edition       string
	shape         string
	usableStorage string
}

//func registerOracleDedicatedHanler (planName string, handler *Oracle_Dedicated_Handler) {
//	expectedPlanName := fmt.Sprintf("Oracle_standalone_%s_%s_%s",
//			handler.level,
//			handler.edition,
//			handler.shape,
//		)
//	
//	if expectedPlanName != planName {
//		panic(fmt.Sprintf("expectedPlanName != planName! %s != %s", expectedPlanName, planName))
//	}
//	
//	register(planName, handler)
//}

//=====================================================================

var oracleDaasClient *oraclecloudrest.OracleDaasClient

func init() {
	oracleDaasClient = oraclecloudrest.NewOracleDaasClient(
			getenv("ORACLE_CLOUD_IDENTITY_DOMAIN_ID"),
			getenv("ORACLE_CLOUD_USERNAME"),
			getenv("ORACLE_CLOUD_PASSWORD"),
			getenv("ORACLE_CLOUD_REST_ENDPOINT"),
			getenv("ORACLE_CLOUD_REST_ENDPOINT_COMPUTE"),
		)
	
	register("Oracle-Cloud_standalone-1", 
		&Oracle_Dedicated_Handler{
			level:   "PAAS",
			edition: "SE",
			shape:   "oc3",
			usableStorage: "30",
		})
	
	register("Oracle-Cloud_standalone-2", 
		&Oracle_Dedicated_Handler{
			level:   "PAAS",
			edition: "EE",
			shape:   "oc4",
			usableStorage: "30",
		})
	
	/*
	register("Oracle_standalone_BASIC_EE_oc3m", 
		&Oracle_Dedicated_Handler{
			level:   "BASIC",
			edition: "EE",
			shape:   "oc1m",
		})
	
	register("Oracle_standalone_BASIC_EE_EP_oc4m", 
		&Oracle_Dedicated_Handler{
			level:   "BASIC",
			edition: "EE_EP",
			shape:   "oc2m",
		})
	*/
}


