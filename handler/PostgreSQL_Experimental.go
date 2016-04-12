package handler

import (
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/pivotal-cf/brokerapi"
	"strings"
)

var postgresUrl string
var postgresUser string
var postgresAdminPassword string
var postgresDashboard string

type Postgresql_sharedHandler struct{}

func (handler *Postgresql_sharedHandler) DoProvision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, ServiceInfo, error) {
	//初始化postgres的链接串
	db, err := sql.Open("postgres", "postgres://"+postgresUser+":"+postgresAdminPassword+"@"+postgresUrl+"?sslmode=disable")

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}
	//测试是否能联通
	err = db.Ping()

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	defer db.Close()

	//不能以instancdID为数据库名字，需要创建一个不带-的数据库名 pg似乎必须用字母开头的变量
	dbname := "d" + getguid()[0:15]
	newusername := "u" + getguid()[0:15]
	newpassword := "p" + getguid()[0:15]
	_, err = db.Query("CREATE USER " + newusername + " WITH PASSWORD '" + newpassword + "'")

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}
	//_, err = db.Query("CREATE DATABASE " + dbname + " WITH OWNER =" + newusername + " ENCODING = 'UTF8'")
	_, err = db.Query("CREATE DATABASE " + dbname + " ENCODING = 'UTF8'")

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	_, err = db.Query("GRANT ALL PRIVILEGES ON DATABASE " + dbname + " TO " + newusername)

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	//为dashbord赋值 todo dashboard应该提供一个界面才对
	DashboardURL := "http://" + postgresDashboard + "?db=" + dbname + "&user=" + newusername + "&pass=" + newpassword

	//赋值隐藏属性
	myServiceInfo := ServiceInfo{
		Url:            postgresUrl,
		Admin_user:     postgresUser,
		Admin_password: postgresAdminPassword,
		Database:       dbname,
		User:           newusername,
		Password:       newpassword,
	}

	provsiondetail := brokerapi.ProvisionedServiceSpec{DashboardURL: DashboardURL, IsAsync: false}

	return provsiondetail, myServiceInfo, nil
}

func (handler *Postgresql_sharedHandler) DoLastOperation(myServiceInfo *ServiceInfo) (brokerapi.LastOperation, error) {
	//因为是同步模式，协议里面并没有说怎么处理啊，统一反馈成功吧！
	return brokerapi.LastOperation{
		State:       brokerapi.Succeeded,
		Description: "It's a sync method!",
	}, nil
}

func (handler *Postgresql_sharedHandler) DoDeprovision(myServiceInfo *ServiceInfo, asyncAllowed bool) (brokerapi.IsAsync, error) {

	//初始化postgres的链接串
	db, err := sql.Open("postgres", "postgres://"+postgresUser+":"+postgresAdminPassword+"@"+postgresUrl+"?sslmode=disable")

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

func (handler *Postgresql_sharedHandler) DoBind(myServiceInfo *ServiceInfo, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, Credentials, error) {
	//初始化postgres的链接串
	db, err := sql.Open("postgres", "postgres://"+postgresUser+":"+postgresAdminPassword+"@"+postgresUrl+"?sslmode=disable")

	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}
	//测试是否能联通
	err = db.Ping()

	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	defer db.Close()

	newusername := "u" + getguid()[0:15]
	newpassword := "p" + getguid()[0:15]

	_, err = db.Query("CREATE USER " + newusername + " WITH PASSWORD '" + newpassword + "'")

	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	_, err = db.Query("GRANT ALL PRIVILEGES ON DATABASE " + myServiceInfo.Database + " TO " + newusername)

	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	mycredentials := Credentials{
		Uri:      "postgres://" + newusername + ":" + newpassword + "@" + myServiceInfo.Url + "/" + myServiceInfo.Database,
		Hostname: strings.Split(myServiceInfo.Url, ":")[0],
		Port:     strings.Split(myServiceInfo.Url, ":")[1],
		Username: newusername,
		Password: newpassword,
		Name:     myServiceInfo.Database,
	}

	myBinding := brokerapi.Binding{Credentials: mycredentials}

	return myBinding, mycredentials, nil

}

func (handler *Postgresql_sharedHandler) DoUnbind(myServiceInfo *ServiceInfo, mycredentials *Credentials) error {
	//初始化postgres的链接串
	db, err := sql.Open("postgres", "postgres://"+postgresUser+":"+postgresAdminPassword+"@"+postgresUrl+"?sslmode=disable")

	if err != nil {
		return err
	}
	//测试是否能联通
	err = db.Ping()

	if err != nil {
		return err
	}

	defer db.Close()

	//要先取消授权才能删除

	_, err = db.Query("REVOKE ALL ON DATABASE " + myServiceInfo.Database + " FROM " + mycredentials.Username)

	if err != nil {
		return err
	}

	//删除用户
	_, err = db.Query("DROP USER " + mycredentials.Username)

	if err != nil {
		return err
	}

	return nil

}

func init() {
	register("PostgreSQL_Experimental", &Postgresql_sharedHandler{})
	postgresUrl = getenv("POSTGRESURL")                     //共享实例的地址
	postgresUser = getenv("POSTGRESUSER")                   //共享实例的mongodb地址
	postgresAdminPassword = getenv("POSTGRESADMINPASSWORD") //共享实例和独立实例的管理员密码
	postgresDashboard = getenv("POSTGRESDASHBOARD")         //dashboardurl
}
