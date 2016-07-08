package handler

import (
	"database/sql"
	//"fmt"
	_ "github.com/mattn/go-oci8"
	"github.com/pivotal-cf/brokerapi"
	"strings"
	"fmt"
	
	_ "github.com/asiainfoLDP/datafoundry_servicebroker_go/handler/odc_daas_rest"
)

// https://github.com/rana/ora
// https://github.com/mattn/go-oci8
// http://www.oracle.com/technetwork/topics/linuxx86-64soft-092277.html

//var oracleAdminUser string
//var oracleAdminPassword string
//var oracleAddress string
//var oracleSID string
//var oracleDashboard string

// user:password@host:port/sid
// sid is the system id to identify a database
//func OracleConnString(user, password, address, sid string) string {
//	return fmt.Sprintf("%s:%s@%s/%s", user, password, address, sid)
//}

//var oracleAdminConnString string

// ...

//type Oracle_sharedHandler struct{}


func (handler *Oracle_Handler) DoProvision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, ServiceInfo, error) {
	//初始化oracle的链接串
	//db, err := sql.Open("oracle", myServiceInfo.Admin_user+":"+myServiceInfo.Admin_password+"@tcp("+myServiceInfo.Url+")/")
	db, err := sql.Open("oci8", handler.connString)
	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}
	defer db.Close()
	
	//测试是否能联通
	err = db.Ping()
	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}
	
	// http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.Oracle.CommonDBATasks.html#Appendix.Oracle.CommonDBATasks.RestrictedSession
	
	var bind_succeeded = false

	//不能以instancdID为数据库名字，需要创建一个不带-的数据库名
	newdbname := "ts" + getguid()[0:14] // max length is 30
	
	{
		//ss := fmt.Sprintf("create tablespace %s size 50m autoextend on next 20m maxsize 256m", newdbname)
		sql_createTS := fmt.Sprintf("create tablespace %s", newdbname)
		println("create tablespace: ", sql_createTS)
		_, err = db.Query(sql_createTS)
		if err != nil {
			return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
		}
		
		defer func() {
			if bind_succeeded {
				return
			}
			
			_, err := db.Query(fmt.Sprintf("drop tablespace %s including contents and datafiles", newdbname))
			if err != nil {
				// ...
				println("bind failed: drop tablespace", newdbname, "failed:", err)
				return
			}
			
			println("bind failed: drop tablespace", newdbname, "succeeded.")
		}()
	}
	
	{
		sql_alterTS := fmt.Sprintf("alter tablespace %s resize 256M", newdbname)
		println("alter tablespace: ", sql_alterTS)
		_, err = db.Query(sql_alterTS)
		if err != nil {
			return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
		}
	}
	
	// need?
	//{
		//sql_tempTS := fmt.Sprintf("ALTER TABLESPACE %s ADD DATAFILE SIZE 100M AUTOEXTEND ON NEXT 25m MAXSIZE UNLIMITED", newdbname)
		//println("create temp tablespace: ", sql_tempTS)
		//_, err = db.Query(sql_tempTS)
		//if err != nil {
		//	return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
		//}
	//}

	newusername := "u" + getguid()[0:15] // max length is 30
	newpassword := "p" + getguid()[0:15] // max length is 30

	// don't work on aws
	//sql_createUser := fmt.Sprintf(`create user %s profile default IDENTIFIED BY %s DEFAULT TABLESPACE %s 
	//			TEMPORARY TABLESPACE %s_temp SIZE 50M autoextend on next 20m maxsize 256m ACCOUNT UNLOCK`,
	//		newusername, newpassword, newdbname, newdbname)
	//println("create user: ", sql_createUser)
	//_, err = db.Query(sql_createUser)
	//if err != nil {
	//	return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	//}
	
	{
		sql_createUser := fmt.Sprintf(`CREATE USER %s IDENTIFIED BY %s`, newusername, newpassword)
		println("create user: ", sql_createUser)
		_, err = db.Query(sql_createUser)
		if err != nil {
			println("create user err:", err.Error())
			return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
		}
		
		defer func() {
			if bind_succeeded {
				return
			}
			
			_, err := db.Query(fmt.Sprintf("drop user %s cascade", newusername))
			if err != nil {
				// ...
				println("bind failed: drop user", newusername, "failed:", err)
				return
			}
			
			println("bind failed: drop user", newusername, "succeeded.")
		}()
	}
	
	
	{
		sql_alterUser := fmt.Sprintf(`ALTER USER %s quota unlimited on %s`, newusername, newdbname)
		println("alter user: ", sql_alterUser)
		_, err = db.Query(sql_alterUser)
		if err != nil {
			return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
		}
	}
	
	{
		sql_grantUser := fmt.Sprintf(`GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, SELECT_CATALOG_ROLE, EXECUTE_CATALOG_ROLE TO %s`, newusername)
		println("grant user: ", sql_grantUser)
		_, err = db.Query(sql_grantUser)
		if err != nil {
			return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
		}
	}
	
	bind_succeeded = true
	
	// just a validation
	/*
	go func() {
		
		connString := OracleConnString(newusername, newpassword, oracleAddress, oracleSID)
		
		db, err := sql.Open("oci8", connString)
		if err != nil {
			println("validation db error:", err.Error())
			return
		}
		defer db.Close()
		
		err = db.Ping()
		if err != nil {
			println("validation db ping error:", err.Error())
			return
		}
		
		table_name := "table_demo"
		sql_createTable := `
CREATE TABLE %s
    ( employee_id    NUMBER(6)
    , first_name     VARCHAR2(20)
    , last_name      VARCHAR2(25) 
         CONSTRAINT emp_last_name_nn_demo NOT NULL
    , email          VARCHAR2(25) 
         CONSTRAINT emp_email_nn_demo     NOT NULL
    , phone_number   VARCHAR2(20)
    , hire_date      DATE  DEFAULT SYSDATE 
         CONSTRAINT emp_hire_date_nn_demo  NOT NULL
    , job_id         VARCHAR2(10)
       CONSTRAINT     emp_job_nn_demo  NOT NULL
    , salary         NUMBER(8,2)
       CONSTRAINT     emp_salary_nn_demo  NOT NULL
    , commission_pct NUMBER(2,2)
    , manager_id     NUMBER(6)
    , department_id  NUMBER(4)
    , dn             VARCHAR2(300)
    , CONSTRAINT     emp_salary_min_demo
                     CHECK (salary > 0) 
    , CONSTRAINT     emp_email_uk_demo
                     UNIQUE (email)
    ) 
   TABLESPACE %s 
   STORAGE (INITIAL     6144  
            NEXT        6144 
            MINEXTENTS     1  
            MAXEXTENTS     5 )
`
	     
		sql_createTable = fmt.Sprintf(sql_createTable, table_name, newdbname)
		_, err = db.Exec(sql_createTable)
		if err != nil {
			println("validation create table error:", err.Error())
			return
		}
		
		println("validation create table succeeded.")
		
		sql_dropTable := fmt.Sprintf(`drop table %s cascade constraint`, table_name)
		println("drop table: ", sql_dropTable)
		_, err = db.Exec(sql_dropTable)
		if err != nil {
			println("validation drop table error:", err.Error())
			return
		}
		
		println("validation drop table succeeded.")
	}()
	*/
	
	
	
	
	//为dashbord赋值 todo dashboard应该提供一个界面才对
	DashboardURL := "" // "http://" + newusername + ":" + newpassword + "@" + oracleDashboard + "?db=" + dbname

	//赋值隐藏属性
	myServiceInfo := ServiceInfo{
		//Url:            oracleAddress,
		//Admin_user:     "root",
		//Admin_password: oracleAdminPassword,
		Database:       newdbname,
		User:           newusername,
		Password:       newpassword,
	}

	provsiondetail := brokerapi.ProvisionedServiceSpec{DashboardURL: DashboardURL, IsAsync: false}

	return provsiondetail, myServiceInfo, nil
}

func (handler *Oracle_Handler) DoLastOperation(myServiceInfo *ServiceInfo) (brokerapi.LastOperation, error) {
	//因为是同步模式，协议里面并没有说怎么处理啊，统一反馈成功吧！
	return brokerapi.LastOperation{
		State:       brokerapi.Succeeded,
		Description: "It's a sync method!",
	}, nil
}

func (handler *Oracle_Handler) DoDeprovision(myServiceInfo *ServiceInfo, asyncAllowed bool) (brokerapi.IsAsync, error) {


	//初始化oracle的链接串
	//db, err := sql.Open("oracle", myServiceInfo.Admin_user+":"+myServiceInfo.Admin_password+"@tcp("+myServiceInfo.Url+")/")
	db, err := sql.Open("oci8", handler.connString)
	if err != nil {
		return brokerapi.IsAsync(false), err
	}
	defer db.Close()
	
	//测试是否能联通
	err = db.Ping()
	if err != nil {
		return brokerapi.IsAsync(false), err
	}

	//删除用户
	_, err1 := db.Query(fmt.Sprintf("drop user %s cascade", myServiceInfo.User))
	if err1 == nil {
		println("user", myServiceInfo.User, "was dropped")
	} else if strings.Index (err1.Error(), "ORA-01918") >= 0 { // usere doesn't exist (already deleted)
		err1 = nil
	}
	
	//删除数据库
	_, err2 := db.Query(fmt.Sprintf("drop tablespace %s including contents and datafiles", myServiceInfo.Database))
	if err2 == nil {
		println("tablespace", myServiceInfo.Database, "was dropped")
	} else if strings.Index (err2.Error(), "ORA-00959") >= 0 { // tablespace doesn't exist (already deleted)
		err2 = nil
	}
	
	if err1 != nil {
		println("unbind drop user failed:", err1.Error())
		if err2 == nil {
			return brokerapi.IsAsync(false), err1
		}
	}

	if err2 != nil {
		println("unbind drop tablesapce failed:", err2.Error())
		return brokerapi.IsAsync(false), err2
	}

	//非异步，无错误的返回
	return brokerapi.IsAsync(false), nil

}

func (handler *Oracle_Handler) DoBind(myServiceInfo *ServiceInfo, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, Credentials, error) {
	
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

	return myBinding, mycredentials, nil

}

func (handler *Oracle_Handler) DoUnbind(myServiceInfo *ServiceInfo, mycredentials *Credentials) error {

	return nil

}

//=====================================================================

func OracleConnString(user, password, address, sid string) string {
	return fmt.Sprintf("%s:%s@%s/%s", user, password, address, sid)
}

type Oracle_Handler struct {
	name string
	
	dedicated bool
	
	adminUser     string
	adminPassword string
	adress        string
	sid           string
	dashboard     string
	
	connString string
}

func newOracleHandler(name string) *Oracle_Handler {
	return &Oracle_Handler {
		name: name,
	}
}

func (oh *Oracle_Handler) setEnvNames(envAaminuser, envAdminPassword, envAddress, envSID, envDashboard string) *Oracle_Handler {
	
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

func (oh *Oracle_Handler) register() *Oracle_Handler {
	register("Oracle_" + oh.name, oh)
	return oh
}

func (oh *Oracle_Handler) setDedicated(d bool) *Oracle_Handler {
	oh.dedicated = d
	return oh
}

//=====================================================================

func init() {
	newOracleHandler("Experimental").
		register().
		setDedicated(false).
		setEnvNames(
			"ORACLEADMINUSER", 
			"ORACLEADMINPASSWORD", 
			"ORACLEADDRESS", 
			"ORACLESID", 
			"ORACLEDASHBOARD",
		)
		
	newOracleHandler("Dedicated").
		register().
		setDedicated(true).
		setEnvNames(
			"ORACLEADMINUSER_DEDICATED", 
			"ORACLEADMINPASSWORD_DEDICATED", 
			"ORACLEADDRESS_DEDICATED", 
			"ORACLESID_DEDICATED", 
			"ORACLEDASHBOARD_DEDICATED",
		)
		
}

// https://docs.oracle.com/cloud/latest/dbcs_dbaas/CSDBR/op-paas-service-dbcs-api-v1.1-instances-%7BidentityDomainId%7D-post.html
