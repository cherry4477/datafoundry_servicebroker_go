package rest

import (
	"fmt"
	"errors"
	"time"
	"strings"
	"bytes"
	"sync"
	//"bufio"
	"io"
	//"os"
	"io/ioutil"
	"crypto/tls"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	//neturl "net/url"
	"encoding/base64"
	"encoding/base32"
	"encoding/json"
	//"encoding/hex"
	//"crypto/md5"
	mathrand "math/rand"
	
	"golang.org/x/crypto/ssh"
)

//==============================================================
// 
//==============================================================

func init() {
}

//==============================================================
// 
//==============================================================

type OracleDaasClient struct {
	identityDomainId string
	
	username string
	password string
	
	// for DaaS
	daasEndPoint  string
	daasUrlPrefix string
	token         string
	
	// for IaaS
	iaasEndPoint  string
	iaasUrlPrefix string
	cookie        string
	cookieMutex   sync.Mutex
}

func NewOracleDaasClient(identityDomainId, username, password, daasEndPoint, iaasEndPoint string) *OracleDaasClient {
	daasEndPoint = strings.TrimRight(daasEndPoint, "/")
	
	if ! strings.HasPrefix(daasEndPoint, "https://") {
		daasEndPoint = "https://" + daasEndPoint
	}
	
	odc := &OracleDaasClient{
		identityDomainId: identityDomainId,
		
		username: username,
		password: password,
		
		daasEndPoint: daasEndPoint,
		iaasEndPoint: iaasEndPoint,
	}
	
	odc.daasUrlPrefix = fmt.Sprintf("%s/paas/service/dbcs/api/v1.1/instances/%s", daasEndPoint, identityDomainId)
	
	req, _ := http.NewRequest("", "/", nil)
	req.SetBasicAuth(odc.username, odc.password)
	odc.token = req.Header.Get("Authorization")
	
	odc.iaasUrlPrefix = odc.iaasEndPoint
	go odc.updateCookie()
	
	return odc
}

func (odc *OracleDaasClient) updateCookie() {
	requestCookie := func() {
		for range [5]struct{}{} {
			bodyParams := struct {
				User     string `json:"user"`
				Password string `json:"passworduser"`
			}{
				User:     odc.username,
				Password: odc.password,
			}
			
			url := fmt.Sprintf("%s/authenticate/", odc.iaasUrlPrefix)
			res, err := odc.doRequest(odc.cookieRequestModifier, "POST", url, bodyParams, nil)
			if err == nil {
				newc := res.Header.Get("Set-Cookie")
				odc.SetCookie(newc)
			
				println("requestCookie new cookie: ", newc)
				break
			}
			
			println("requestCookie error: ", err.Error())
			
			<- time.After(5 * time.Second)
		}
	}
	
	requestCookie()
	
	ticker := time.Tick(3 * time.Hour)
	for range ticker {
		requestCookie()
	}
}

func (odc *OracleDaasClient) Cookie() string {
	var c string
	odc.cookieMutex.Lock()
	c = odc.cookie
	odc.cookieMutex.Unlock()
	return c
}

func (odc *OracleDaasClient) SetCookie(c string) {
	odc.cookieMutex.Lock()
	odc.cookie = c
	odc.cookieMutex.Unlock()
}

type requestModifier func (req *http.Request)

func (odc *OracleDaasClient) cookieRequestModifier (req *http.Request) {
	req.Header.Set("Content-Type", "application/oracle-compute-v3+json")
}

func (odc *OracleDaasClient) iaasRequestModifier (req *http.Request) {
	req.Header.Set("Content-Type", "application/oracle-compute-v3+json")
	req.Header.Set("Accept", "application/oracle-compute-v3+json")
	req.Header.Set("Cookie", odc.Cookie())
}

func (odc *OracleDaasClient) daasRequestModifier (req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	//req.Header.Set("X-ID-TENANT-NAME", odc.identityDomainId)
	req.Header["X-ID-TENANT-NAME"] = []string{odc.identityDomainId}
	req.Header.Set("Authorization", odc.token)
}

func (odc *OracleDaasClient) request (reqMod requestModifier, method string, url string, body []byte, timeout time.Duration) (*http.Response, error) {
	var req *http.Request
	var err error
	if len(body) == 0 {
		req, err = http.NewRequest(method, url, nil)
	} else {
		req, err = http.NewRequest(method, url, bytes.NewReader(body))
	}
	
	if err != nil {
		return nil, err
	}
	
	reqMod(req)
	
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transCfg,
		Timeout: timeout,
	}
	
	fmt.Println("request:", method, url)
	fmt.Println("request.body:", string(body))
	fmt.Println("request.Header:", req.Header)
	
	return client.Do(req)
}

const GeneralRequestTimeout = time.Duration(120) * time.Second

func (odc *OracleDaasClient) doRequest (reqMod requestModifier, method, url string, bodyParams interface{}, into interface{}) (res *http.Response, err error) {
	var body []byte
	if bodyParams != nil {
		body, err = json.Marshal(bodyParams)
		if err != nil {
			return
		}
	}
	
	res, err = odc.request(reqMod, method, url, body, GeneralRequestTimeout)
	if err != nil {
		return
	}
	defer res.Body.Close()
	
	var data []byte
	data, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	
	fmt.Println("response.Status =", res.StatusCode, res.Status)
	fmt.Println("response.Header =", res.Header)
	
	//println("22222 len(data) = ", len(data), " , res.StatusCode = ", res.StatusCode)
	
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		err = errors.New(string(data))
	} else {
		if into != nil {
			//println("into data = ", string(data), "\n")
		
			err = json.Unmarshal(data, into)
		}
	}
	
	return
}

func (odc *OracleDaasClient) GetUrl (url string, into interface{}) (res *http.Response, err error) {
	return odc.doRequest(odc.daasRequestModifier, "GET", url, nil, into)
}

func (odc *OracleDaasClient) Get (uri string, into interface{}) (res *http.Response, err error) {
	return odc.doRequest(odc.daasRequestModifier, "GET", odc.daasUrlPrefix + uri, nil, into)
}

func (odc *OracleDaasClient) Delete (uri string, into interface{}) (res *http.Response, err error) {
	return odc.doRequest(odc.daasRequestModifier, "DELETE", odc.daasUrlPrefix + uri, nil, into)
}

func (odc *OracleDaasClient) Post (uri string, body interface{}, into interface{}) (res *http.Response, err error) {
	return odc.doRequest(odc.daasRequestModifier, "POST", odc.daasUrlPrefix + uri, body, into)
}

func (odc *OracleDaasClient) Put (uri string, body interface{}, into interface{}) (res *http.Response, err error) {
	return odc.doRequest(odc.daasRequestModifier, "PUT", odc.daasUrlPrefix + uri, body, into)
}

//===============================================================
// 
//===============================================================

/*
func ShapeSpec(shape string) (string, string) {
	switch shape {
	default:
		return "Unknown", "Unknown"
	case "oc3":
		return "1_OCPU", "7.5GB_Memory"
	case "oc4":
		return "2_OCPUs", "15GB_Memory"
	case "oc5":
		return "4_OCPUs", "30GB_Memory"
	case "oc6":
		return "8_OCPUs", "60GB_Memory"
	case "oc1m":
		return "1_OCPU", "15GB_Memory"
	case "oc2m":
		return "2_OCPUs", "30GB_Memory"
	case "oc3m":
		return "4_OCPUs", "60GB_Memory"
	case "oc4m":
		return "8_OCPUs", "120GB_Memory"
	case "oc5m":
		return "16_OCPUs", "240GB_Memory"
	}
}
*/

type OracleDaasCreateParameter struct {
	AdminPassword     string         `json:"adminPassword"`
	BackupDestination string         `json:"backupDestination"`
		// BOTH | NONE
	Charset  string         `json:"charset,omitempty"`
		// not required, default is AL32UTF8
	CloudStorageContainer  string         `json:"cloudStorageContainer,omitempty"`
	CloudStoragePwd  string         `json:"cloudStoragePwd,omitempty"`
	CloudStorageUser  string         `json:"cloudStorageUser,omitempty"`
	DbconsolePort  string         `json:"dbconsolePort,omitempty"`
		// Database Console port for 11g Oracle Database. This value defaults to: 1158
	EmexpressPort  string         `json:"emexpressPort,omitempty"`
		// EM Express Console port for 12c Oracle Database. This value defaults to: 5500
	IsRac  string         `json:"isRac,omitempty"`
		// Specify if a cluster database using Oracle Real Application Clusters should be configured. 
		// Valid values are yes and no. Default value is no.
	ListenerPort  string         `json:"listenerPort,omitempty"`
		// Listener Port for connection to the Oracle Database. 
		// This value defaults to: 1521
	Ncharset  string         `json:"ncharset,omitempty"`
		// National Character Set for the Database as a Service instance. 
		// Default value is AL16UTF16. Valid values are AL16UTF16 and UTF8.
	PdbName  string         `json:"pdbName,omitempty"`
		// This attribute is valid when Database as a Service instance is configured with version 12c.
		// Pluggable Database Name for the Database as a Service instance. Default value is pdb1.
	Sid  string         `json:"sid,omitempty"`
		// Database Name (sid) for the Database as a Service instance. 
		// Default value is ORCL
	Timezone  string         `json:"timezone,omitempty"`
	Type  string         `json:"type,omitempty"`
		// Component type to which the set of parameters applies. 
		// Valid values are: "db" - Oracle Database 
	UsableStorage  string         `json:"usableStorage,omitempty"`
		// Storage volume size for data. Default value is 25GB. 
		// Minimum allowed size is 15GB. 
		// Maximum allowed size is 500GB if backup destination is specified 
		// and 1000GB if no backup destination is specified. 
		// Backup volume size is calculated based on data size.
	// failoverDatabase
}

type OracleDaasCreateConfig struct {
	ServiceName      string         `json:"serviceName"`
			// Must not exceed 50 characters.
			// Must start with a letter.
			// Must contain only letters, numbers, or hyphens.
			// Must not contain any other special characters.
			// Must be unique within the identity domain.
	Description      string         `json:"description"`
	Level            string         `json:"level"`
			// PAAS | BASIC
	SubscriptionType string         `json:"subscriptionType"`
			// HOURLY | MONTHLY // must be MONTHLY for this service broker
	VmPublicKeyText  string         `json:"vmPublicKeyText"`
			// ex: "vmPublicKeyText": "ssh-rsa AAAAB3NzaC1yc2EAAAABJ= rsa-key-20150105"
	Version          string         `json:"version"`
			// 11.2.0.4 or 12.1.0.2 (12 | 11) // use 11
	
	Edition          string         `json:"edition"`
			// SE | EE | EE_HP | EE_EP 
			// https://cloud.oracle.com/en_US/database?tabID=1406491812773
			// https://docs.oracle.com/cloud/latest/dbcs_dbaas/CSDBR/op-paas-service-dbcs-api-v1.1-instances-%7BidentityDomainId%7D-post.html#examples
	Shape            string         `json:"shape"`
			// oc3: 1 OCPU, 7.5 GB memory
			// oc4: 2 OCPUs, 15 GB memory
			// oc5: 4 OCPUs, 30 GB memory
			// oc6: 8 OCPUs, 60 GB memory
			// oc1m: 1 OCPU, 15 GB memory
			// oc2m: 2 OCPUs, 30 GB memory
			// oc3m: 4 OCPUs, 60 GB memory
			// oc4m: 8 OCPUs, 120 GB memory
	
	Parameters []*OracleDaasCreateParameter `json:"parameters,omitempty"`
			// for PAAS only
}

func NewOracleDaasCreateConfig_Basic(serviceName, edition, shape, vmPublicKeyText string) *OracleDaasCreateConfig {
	return &OracleDaasCreateConfig{
		ServiceName: serviceName,
		Edition:     edition,
		Shape:       shape,
		
		Version:          "11.2.0.4",
		Level:            "BASIC",
		SubscriptionType: "MONTHLY",
		
		VmPublicKeyText: vmPublicKeyText,
		Description:     "my db",
		
		Parameters: nil,
	}
}

func NewOracleDaasCreateConfig_PaaS(serviceName, edition, shape, vmPublicKeyText, adminPassword, usableStorage string) *OracleDaasCreateConfig {
	config := NewOracleDaasCreateConfig_Basic(
			serviceName, edition, shape, vmPublicKeyText,
		)
	config.Level = "PAAS"
	param := &OracleDaasCreateParameter {
			AdminPassword: adminPassword,
			UsableStorage: usableStorage,
			
			Type: "db",
			Sid: "ORCL",
			BackupDestination: "NONE",
		}
	config.Parameters = []*OracleDaasCreateParameter{param}
	return config
}

func (odc *OracleDaasClient) CreateDatabaseInstance (config *OracleDaasCreateConfig) (res *http.Response, err error) {
	return odc.Post("", config, nil)
}

func (odc *OracleDaasClient) DeleteDatabaseInstance (serviceId string) (res *http.Response, err error) {
	return odc.Delete(fmt.Sprintf("/%s", serviceId), nil)
}

/*
{
  "service_name": "db12c-eeep",
  "version": "12.1.0.2",
  "status": "Running",
  "description": "Example service instance",
  "identity_domain": "usexample",
  "creation_time": "Mon Apr 20 15:47:57 UTC 2015",
  "last_modified_time": "Mon Apr 20 15:47:57 UTC 2015",
  "created_by": "dbaasadmin",
  "service_uri": "https:\/\/dbaas.oraclecloud.com:443\/paas\/service\/dbcs\/api\/v1.1\/instances\/usexample\/db12c-eeep",
  "num_nodes": 1,
  "level": "PAAS",
  "edition": "EE_EP",
  "shape": "oc3",
  "subscriptionType": "MONTHLY",
  "creation_job_id": "64402",
  "num_ip_reservations": 1,
  "backup_destination": "BOTH",
  "cloud_storage_container": "Storage-usexample\/dbcsbackups",
  "sid": "ORCL",
  "pdbName": "PDB1",
  "listenerPort": 1521,
  "em_url": "https:\/\/129.152.132.225:5500\/em",
  "connect_descriptor": "db12c-eeep:1521\/PDB1.usexample.oraclecloud.internal",
  "apex_url": "https:\/\/129.152.132.225\/apex\/pdb1\/",
  "glassfish_url": "https:\/\/129.152.132.225:4848",
  "dbaasmonitor_url": "https:\/\/129.152.132.225\/dbaas_monitor",
  "pdbss_url": "https:\/\/129.152.132.225\/apex\/f?p=PDBSS",
}
*/
type InstanceInfo struct {
	Status       string `json:"status"`
	SID          string `json:"sid"`
	PdbName      string `json:"pdbName"`
	ListenerPort int    `json:"listenerPort"`
	ServiceURI   string `json:"service_uri"`
}

//   /paas/service/dbcs/api/v1.1/instances/{identityDomainId}
func (odc *OracleDaasClient) ViewDatabaseInstance (serviceId string, result *InstanceInfo) (res *http.Response, err error) {
	return odc.Get(fmt.Sprintf("/%s", serviceId), result)
}

/*
BASIC
[{
  "status": "Running",
  "creation_job_id": "5740044",
  "creation_time": "Thu Jul 14 9:52:10 UTC 2016",
  "created_by": "liuxu@asiainfo.com",
  "shape": "oc3m",
  "initialPrimary": true,
  "storageAllocated": 32768,
  "reservedIP": "129.144.9.216",
  "hostname": "svc-db-ybqdagemy3rxc"
}]

PAAS
[{
  "status": "Running",
  "creation_job_id": "5745893",
  "creation_time": "Fri Jul 15 7:14:40 UTC 2016",
  "created_by": "liuxu@asiainfo.com",
  "shape": "oc3",
  "sid": "ORCL",
  "listenerPort": 1521,
  "connect_descriptor": "svc-db-vhkguni2budig:1521\/ORCL.aibdx.oraclecloud.internal",
  "connect_descriptor_with_public_ip": "129.144.9.189:1521\/ORCL.aibdx.oraclecloud.internal",
  "initialPrimary": true,
  "storageAllocated": 217088,
  "reservedIP": "129.144.9.189",
  "hostname": "svc-db-vhkguni2budig"
}]
*/
type InstanceServerInfo struct {
	Status            string `json:"status"`
	StorageAllocated  int    `json:"storageAllocated"`
	ConnectDescriptor string `json:"connect_descriptor_with_public_ip"`
	SID               string `json:"sid"`
	ReservedIP        string `json:"reservedIP"`
	ListenerPort      int    `json:"listenerPort"`     // only for PAAS
}

//   /paas/service/dbcs/api/v1.1/instances/{identityDomainId}
func (odc *OracleDaasClient) ViewDatabaseInstanceServers (serviceId string, result *[]InstanceServerInfo) (res *http.Response, err error) {
	return odc.Get(fmt.Sprintf("/%s/servers", serviceId), result)
}

type OracleDaasScaleConfig struct {
	AdditionalStorage string        `json:"additionalStorage"`
	Shape             string        `json:"shape"`
	Usage             string        `json:"usage"`
}

func (odc *OracleDaasClient) ScaleDatabaseInstance (serviceId string, config *OracleDaasScaleConfig) (res *http.Response, err error) {
	return odc.Put(fmt.Sprintf("/%s", serviceId), config, nil)
}


/*
{
  "service_name": "svc-db-ybqdagemy3rxc",
  "version": "11.2.0.4",
  "status": "Running",
  "description": "my db",
  "identity_domain": "aibdx",
  "creation_time": "Thu Jul 14 9:52:10 UTC 2016",
  "last_modified_time": "Thu Jul 14 9:52:10 UTC 2016",
  "created_by": "liuxu@asiainfo.com",
  "sm_plugin_version": "16.3.1-132",
  "service_uri": "https:\/\/dbaas.oraclecloud.com:443\/paas\/service\/dbcs\/api\/v1.1\/instances\/aibdx\/svc-db-ybqdagemy3rxc",
  "message": ["SSH access to VM [DB_1\/vm-1] succeeded..."],
  "job_start_date": "Thu Jul 14 09:52:15 GMT 2016",
  "job_status": "Succeeded",
  "job_operation": "create-dbaas-service",
  "job_request_params": {
    "edition": "EE",
    "vmPublicKeyText": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC0D\/P2qHdVrNmxaw7h0TfdOElq4xOyp+xkftCf6\/8EgEkj5E8EoSlsVNIuI08rmVCTzUBZwCjl7frfM5RPP9mQhyjhRtXpRbW8xcxqLhU\/hXtPBIy6pp+Of6hdfRUc0uX1gppJg5ACHsI9Gtq2q8G9q3l7eM5LQMHpOnVwsNEI5TcmksRGE9VKxW6GnB5YOyP75zUEr8OfAMrhtMNP4GNda8Ey9roe\/zBjSBQQmsB2x3YkJpprSB\/dEYUtMYjSbaEB9GH42+TX9rTBk8\/ZVNebMDxasxYePWZOm09vDdPoiNsb\/tZy3lejYu2e7jvbLnGpRG++tH\/JSwVkEUvf1bRCNZG\/2VPKInyn8PXijkHqcoopWKX8qtcY\/jNDhLj3bOs9yrPn2R9bGXOtMHTSK9tLeUFh135XGofBXMKNUs6CqXaEr2xLktOfOJh1TBywTQazxnJDd3KKWR3F35QPddgxVrI3IyH0vnrJz+J+oaphYguSQpCn2muJk5TaflnCyfsazUm6HlaT3EKce92BzwGkWXRfqil7BOkFhQYK59dhST7vRhvqmZ4OIUgeOeUKVAj+JSk6xU+b5h7tz1Fin6lExDd72bm5Avx24N\/Q2hmpBCwwDcxTNEYk0nTEOYmli+OuiY36w2o\/fpNtonUGNX9\/l8DRmvmxcugL6qeGoW8nAQ== rsa-key-20160714",
    "count": "2",
    "provisioningTimeout": "180",
    "subscriptionType": "MONTHLY",
    "listenerPort": "1521",
    "dbConsolePort": "1158",
    "version": "11.2.0.4",
    "serviceName": "svc-db-ybqdagemy3rxc",
    "namespace": "dbaas",
    "timezone": "UTC",
    "level": "BASIC",
    "tenant": "aibdx",
    "serviceInstance": "svc-db-ybqdagemy3rxc",
    "description": "my db",
    "failoverDatabase": "false",
    "ncharset": "AL16UTF16",
    "emExpressPort": "5500",
    "trial": "false",
    "sid": "ORCL",
    "noRollback": "false",
    "operationName": "create-dbaas-service",
    "goldenGate": "false",
    "backupDestination": "NONE",
    "serviceVersion": "11.2.0.4",
    "charset": "AL32UTF8",
    "shape": "oc3m",
    "identity_domain_id": "aibdx",
    "serviceType": "dbaas",
    "usableStorage": "25",
    "disasterRecovery": "false",
    "server_base_uri": "https:\/\/dbaas.oraclecloud.com:443\/paas\/service\/dbcs\/",
    "computeSiteName": "US006_Z21",
    "isRac": "false"
  }
}
*/
type JobStatusInfo struct {
	Status     string   `json:"status"`
	JobStatus  string   `json:"job_status"`
	Message    []string `json:"message"`
	ServiceURI string   `json:"service_uri"`
}

// requestName: create | delete | scale
func (odc *OracleDaasClient) ViewJobStatus(requestName, jobUrl string, result *JobStatusInfo) (res *http.Response, err error) {
	return odc.GetUrl(jobUrl, result)
}

//---

/*
{
  "dst_list": "seclist:/Compute-acme/jack.jones@example.com/allowed_video_servers",
  "name": "/Compute-acme/jack.jones@example.com/es_to_videoservers_stream",
  "src_list": "seciplist:/Compute-acme/jack.jones@example.com/es_iplist",
  "application": "/Compute-acme/jack.jones@example.com/video_streaming_udp",
  "action": "PERMIT",
  "disabled": false
}

Results per page:	
8 result(s) as of Jul 19, 2016 8:33:13 AM UTCRefresh
							
Status   Rule Name   Source   Destination   Ports   Description   Rule Type   Actions
This access rule is enabled.	ora_p2_ssh	PUBLIC-INTERNET	DB	22	 	DEFAULT	
This access rule is enabled.	ora_p2_dblistener	PUBLIC-INTERNET	DB	1521	 	DEFAULT	
This access rule is disabled.	ora_p2_http	PUBLIC-INTERNET	DB	80	 	DEFAULT	
This access rule is disabled.	ora_p2_httpssl	PUBLIC-INTERNET	DB	443	 	DEFAULT	

*/

type SecurityRuleUpdate struct {
	DstList     string `json:"dst_list"`
	Name        string `json:"name"`
	SrcList     string `json:"src_list"`
	Application string `json:"application"`
	Action      string `json:"action"`
	Disabled    bool   `json:"disabled"`
}

// source: "PUBLIC-INTERNET"
// destination: "DB"
// rule-name: "ora_p2_dblistener"

// todo: oracle docs is not very clear. Not successful to enable rules.
func (odc *OracleDaasClient) SetSecurityRuleEnabled (instanceName, ruleName, sourceName, destName string, enabled bool) (res *http.Response, err error) {
	body := &SecurityRuleUpdate{
		DstList:     fmt.Sprintf("seclist:/Compute-%s/%s/%s", odc.identityDomainId, odc.username, destName),
		Name:        fmt.Sprintf("/Compute-%s/%s/%s", odc.identityDomainId, odc.username, ruleName) ,
		SrcList:     fmt.Sprintf("seciplist:/Compute-%s/%s/%s", odc.identityDomainId, odc.username, sourceName),
		Application: fmt.Sprintf("/Compute-%s/%s/%s", odc.identityDomainId, odc.username, instanceName),
		Action:      "PERMIT",
		Disabled:    !enabled,
	}
	
	into := &SecurityRuleUpdate{}
	
	url := fmt.Sprintf("%s/secrule/Compute-%s/%s/%s", odc.iaasUrlPrefix, odc.identityDomainId, odc.username, ruleName)
	
	return odc.doRequest(odc.iaasRequestModifier, "PUT", url, body, into)
}

//===============================================================
// 
//===============================================================
/*
func getMd5(content []byte) []byte {
	md5Ctx := md5.New()
	md5Ctx.Write(content)
	return md5Ctx.Sum(nil)
}

func getHexMd5(content string) string {
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(content))
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(getMd5([]byte(content)))
}

func getBase64Md5(content string) string {
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(content))
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(getMd5([]byte(content)))
}
*/

func NewElevenLengthID() string {
	t := time.Now().UnixNano()
	bs := make([]byte, 8)
	for i := uint(0); i < 8; i ++ {
		bs[i] = byte((t >> i) & 0xff)
	}
	return string(base64.RawURLEncoding.EncodeToString(bs))
}

var base32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")
func NewThirteenLengthID() string {
	t := time.Now().UnixNano()
	bs := make([]byte, 8)
	for i := uint(0); i < 8; i ++ {
		bs[i] = byte((t >> i) & 0xff)
	}
	
	dest := make([]byte, 16)
	base32Encoding.Encode(dest, bs)
	return string(dest[:13])
}


// Use a password that is 8 to 30 characters long, 
// contains at least one lowercase letter, one uppercase letter, 
// one number, one of the following characters -_# and no white space character
var base64Encoding = base64.URLEncoding.WithPadding('#')
func NewPassword8_30() string {
	bs := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, bs)
	if err != nil {
		for i := range bs {
			bs[i] = byte(mathrand.Intn(256))
		}
	}
	
	s := base64Encoding.EncodeToString(bs)
	i := mathrand.Intn(9) + 6
	return s[i:] + s[:i]
}

// copied from https://github.com/golang-samples/cipher/blob/7ddd835695a21db3d00e869f59cdf9339dde66c6/crypto/rsa_keypair.go

func GenerateRsaPair() (privateKey, publicKey string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}
	err = priv.Validate()
	if err != nil {
		return
	}

	priv_der := x509.MarshalPKCS1PrivateKey(priv)

	// pem.Block
	// blk pem.Block
	priv_blk := pem.Block {
		Type: "RSA PRIVATE KEY",
		Headers: nil,
		Bytes: priv_der,
	}

	// Resultant private key in PEM format.
	// priv_pem string
	privateKey = string(pem.EncodeToMemory(&priv_blk))
	println("private:", privateKey)
	
	// ...
	
	pub := priv.PublicKey
	
	// pub.pem
	//pub_der, err := x509.MarshalPKIXPublicKey(&pub)
	//if err != nil {
	//	return
	//}
	//
	//pub_blk := pem.Block {
	//	Type: "PUBLIC KEY",
	//	Headers: nil,
	//	Bytes: pub_der,
	//}
	//publicKey = string(pem.EncodeToMemory(&pub_blk))
	//println("public:", publicKey)
	
	sshpub, err := ssh.NewPublicKey(&pub)
	if err != nil {
		return
	}
	publicKey = string(ssh.MarshalAuthorizedKey(sshpub))
	publicKey = strings.TrimRight(publicKey, "\n")
	publicKey = fmt.Sprintf("%s rsa-key-%s", publicKey, time.Now().Format("20060102"))
	println("public:", publicKey)
	
	return
}