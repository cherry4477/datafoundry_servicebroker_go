package handler

import (
	"database/sql"
	//"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/pivotal-cf/brokerapi"
	"strings"
)

var mysqlUrl string
var mysqlAdminPassword string
var mysqlDashboard string

type Mysql_sharedHandler struct{}

func (handler *Mysql_sharedHandler) DoProvision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, ServiceInfo, error) {
	//初始化mysql的链接串
	db, err := sql.Open("mysql", "root:"+mysqlAdminPassword+"@tcp("+mysqlUrl+")/")

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}
	//测试是否能联通
	err = db.Ping()

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	defer db.Close()

	//不能以instancdID为数据库名字，需要创建一个不带-的数据库名
	dbname := getguid()[0:15]
	_, err = db.Query("CREATE DATABASE " + dbname + " DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci")

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	newusername := getguid()[0:15]
	newpassword := getguid()[0:15]

	_, err = db.Query("GRANT ALL ON " + dbname + ".* TO '" + newusername + "'@'%' IDENTIFIED BY '" + newpassword + "'")

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	//为dashbord赋值 todo dashboard应该提供一个界面才对
	DashboardURL := "http://" + newusername + ":" + newpassword + "@" + mysqlDashboard + "?db=" + dbname

	//赋值隐藏属性
	myServiceInfo := ServiceInfo{
		Url:            mysqlUrl,
		Admin_user:     "root",
		Admin_password: mysqlAdminPassword,
		Database:       dbname,
		User:           newusername,
		Password:       newpassword,
	}

	provsiondetail := brokerapi.ProvisionedServiceSpec{DashboardURL: DashboardURL, IsAsync: false}

	return provsiondetail, myServiceInfo, nil
}

func (handler *Mysql_sharedHandler) DoLastOperation(myServiceInfo *ServiceInfo) (brokerapi.LastOperation, error) {
	//因为是同步模式，协议里面并没有说怎么处理啊，统一反馈成功吧！
	return brokerapi.LastOperation{
		State:       brokerapi.Succeeded,
		Description: "It's a sync method!",
	}, nil
}

func (handler *Mysql_sharedHandler) DoDeprovision(myServiceInfo *ServiceInfo, asyncAllowed bool) (brokerapi.IsAsync, error) {

	//初始化mysql的链接串
	//db, err := sql.Open("mysql", myServiceInfo.Admin_user+":"+myServiceInfo.Admin_password+"@tcp("+myServiceInfo.Url+")/")
	db, err := sql.Open("mysql", "root:"+mysqlAdminPassword+"@tcp("+mysqlUrl+")/")
	if err != nil {
		return brokerapi.IsAsync(false), err
	}
	//测试是否能联通
	err = db.Ping()

	if err != nil {
		return brokerapi.IsAsync(false), err
	}

	defer db.Close()

	//删除数据库
	_, err = db.Query("DROP DATABASE " + myServiceInfo.Database)

	if err != nil {
		return brokerapi.IsAsync(false), err
	}

	//删除用户
	_, err = db.Query("DROP USER " + myServiceInfo.User)

	if err != nil {
		return brokerapi.IsAsync(false), err
	}

	//非异步，无错误的返回
	return brokerapi.IsAsync(false), nil

}

func (handler *Mysql_sharedHandler) DoBind(myServiceInfo *ServiceInfo, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, Credentials, error) {
	//初始化mysql的链接串
	//db, err := sql.Open("mysql", myServiceInfo.Admin_user+":"+myServiceInfo.Admin_password+"@tcp("+myServiceInfo.Url+")/")
	db, err := sql.Open("mysql", "root:"+mysqlAdminPassword+"@tcp("+mysqlUrl+")/")
	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}
	//测试是否能联通
	err = db.Ping()

	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	defer db.Close()

	newusername := getguid()[0:15]
	newpassword := getguid()[0:15]

	_, err = db.Query("GRANT ALL ON " + myServiceInfo.Database + ".* TO '" + newusername + "'@'%' IDENTIFIED BY '" + newpassword + "'")

	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	mycredentials := Credentials{
		Uri:      "mysql://" + newusername + ":" + newpassword + "@" + myServiceInfo.Url + "/" + myServiceInfo.Database,
		Hostname: strings.Split(myServiceInfo.Url, ":")[0],
		Port:     strings.Split(myServiceInfo.Url, ":")[1],
		Username: newusername,
		Password: newpassword,
		Name:     myServiceInfo.Database,
	}

	myBinding := brokerapi.Binding{Credentials: mycredentials}

	return myBinding, mycredentials, nil

}

func (handler *Mysql_sharedHandler) DoUnbind(myServiceInfo *ServiceInfo, mycredentials *Credentials) error {
	//初始化mysql的链接串
	//db, err := sql.Open("mysql", myServiceInfo.Admin_user+":"+myServiceInfo.Admin_password+"@tcp("+myServiceInfo.Url+")/")
	db, err := sql.Open("mysql", "root:"+mysqlAdminPassword+"@tcp("+mysqlUrl+")/")
	if err != nil {
		return err
	}
	//测试是否能联通
	err = db.Ping()

	if err != nil {
		return err
	}

	defer db.Close()

	//删除用户
	_, err = db.Query("DROP USER " + mycredentials.Username)

	if err != nil {
		return err
	}

	return nil

}

func init() {
	register("Mysql_Experimental", &Mysql_sharedHandler{})
	mysqlUrl = getenv("MYSQLURL")                     //共享实例的mongodb地址
	mysqlAdminPassword = getenv("MYSQLADMINPASSWORD") //共享实例和独立实例的管理员密码
	mysqlDashboard = getenv("MYSQLDASHBOARD")         //dashboard地址
}
