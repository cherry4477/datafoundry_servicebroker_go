package handler

import (
	"github.com/pivotal-cf/brokerapi"
	"gopkg.in/mgo.v2"
	"strings"
)

var mongoUrl string
var mongoAdminUser string
var mongoAdminPassword string
var mongoDashboard string

type Mongodb_aws_sharedHandler struct{}

func (handler *Mongodb_aws_sharedHandler) DoProvision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, ServiceInfo, error) {
	//初始化mongodb的链接串
	session, err := mgo.Dial(mongoUrl) //连接数据库
	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	mongodb := session.DB("admin") //数据库名称
	err = mongodb.Login(mongoAdminUser, mongoAdminPassword)
	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	//todo: looks the user/pass pair is never used, remove it?
	
	//创建一个名为instanceID的数据库，并随机的创建用户名和密码，这个用户名是该数据库的管理员
	newdb := session.DB(instanceID)
	newusername := getguid()
	newpassword := getguid()
	//为dashbord赋值 todo dashboard应该提供一个界面才对
	//DashboardURL := "http://" + mongoDashboard + "/index.php?action=autologin.index&user=" + newusername + "&pass=" + newpassword + "&instance=" + instanceID
	DashboardURL := "http://" + mongoDashboard + "/index.php"

	//这个服务很快，所以通过同步模式直接返回了
	err = newdb.UpsertUser(&mgo.User{
		Username: newusername,
		Password: newpassword,
		Roles: []mgo.Role{
			mgo.Role(mgo.RoleDBAdmin),
		},
	})

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	//赋值隐藏属性
	myServiceInfo := ServiceInfo{
		Url:            mongoUrl,
		Admin_user:     mongoAdminUser,
		Admin_password: mongoAdminPassword,
		Database:       instanceID,
		User:           newusername,
		Password:       newpassword,
	}

	provsiondetail := brokerapi.ProvisionedServiceSpec{DashboardURL: DashboardURL, IsAsync: false}

	return provsiondetail, myServiceInfo, nil
}

func (handler *Mongodb_aws_sharedHandler) DoLastOperation(myServiceInfo *ServiceInfo) (brokerapi.LastOperation, error) {
	//因为是同步模式，协议里面并没有说怎么处理啊，统一反馈成功吧！
	return brokerapi.LastOperation{
		State:       brokerapi.Succeeded,
		Description: "It's a sync method!",
	}, nil
}

func (handler *Mongodb_aws_sharedHandler) DoDeprovision(myServiceInfo *ServiceInfo, asyncAllowed bool) (brokerapi.IsAsync, error) {
	//初始化mongodb的链接串
	//session, err := mgo.Dial(myServiceInfo.Url) //连接数据库
	session, err := mgo.Dial(mongoUrl) //连接数据库
	if err != nil {
		return brokerapi.IsAsync(false), err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	mongodb := session.DB("admin") //数据库名称
	//err = mongodb.Login(myServiceInfo.Admin_user, myServiceInfo.Admin_password)
	err = mongodb.Login(mongoAdminUser, mongoAdminPassword)
	if err != nil {
		return brokerapi.IsAsync(false), err
	}

	//选择服务创建的数据库
	userdb := session.DB(myServiceInfo.Database)
	//这个服务很快，所以通过同步模式直接返回了
	err = userdb.DropDatabase()

	if err != nil {
		return brokerapi.IsAsync(false), err
	}

	//非异步，无错误的返回
	return brokerapi.IsAsync(false), nil
}

func (handler *Mongodb_aws_sharedHandler) DoBind(myServiceInfo *ServiceInfo, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, Credentials, error) {
	//初始化mongodb的两个变量
	//mongodburl := myServiceInfo.Url
	mongodburl := mongoUrl
	//share 模式只能是该数据库
	mongodbname := myServiceInfo.Database
	//share 模式，只是这个数据库的读写
	mongodbrole := mgo.RoleReadWrite
	//完成变量赋值以后，开始准备创建用户
	//初始化mongodb的链接串
	session, err := mgo.Dial(mongodburl) //连接数据库
	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	mongodb := session.DB("admin") //数据库名称
	//err = mongodb.Login(myServiceInfo.Admin_user, myServiceInfo.Admin_password)
	err = mongodb.Login(mongoAdminUser, mongoAdminPassword)
	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	//去创建一个用户，权限为RoleReadWrite
	userdb := session.DB(mongodbname)
	newusername := getguid()
	newpassword := getguid()
	//这个服务很快，所以通过同步模式直接返回了。再说了目前bind的协议只有同步的模式
	err = userdb.UpsertUser(&mgo.User{
		Username: newusername,
		Password: newpassword,
		Roles: []mgo.Role{
			mongodbrole,
		},
	})

	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	mycredentials := Credentials{
		Uri:      "mongodb://" + newusername + ":" + newpassword + "@" + mongodburl + "/" + mongodbname,
		Hostname: strings.Split(mongodburl, ":")[0],
		Port:     strings.Split(mongodburl, ":")[1],
		Username: newusername,
		Password: newpassword,
		Name:     mongodbname,
	}

	myBinding := brokerapi.Binding{Credentials: mycredentials}

	return myBinding, mycredentials, nil
}

func (handler *Mongodb_aws_sharedHandler) DoUnbind(myServiceInfo *ServiceInfo, mycredentials *Credentials) error {
	//初始化mongodb的两个变量
	//mongodburl := myServiceInfo.Url
	mongodburl := mongoUrl
	mongodbname := myServiceInfo.Database
	//初始化mongodb的链接串
	session, err := mgo.Dial(mongodburl) //连接数据库
	if err != nil {
		return err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	mongodb := session.DB("admin") //数据库名称
	//err = mongodb.Login(myServiceInfo.Admin_user, myServiceInfo.Admin_password)
	err = mongodb.Login(mongoAdminUser, mongoAdminPassword)
	if err != nil {
		return err
	}

	//选择服务创建的数据库
	userdb := session.DB(mongodbname)
	//这个服务很快，所以通过同步模式直接返回了
	err = userdb.RemoveUser(mycredentials.Username)

	if err != nil {
		return err
	}

	return nil
}

func init() {
	register("MongoDB_Experimental", &Mongodb_aws_sharedHandler{})
	mongoUrl = getenv("MONGOURL")                     //共享实例的mongodb地址
	mongoAdminUser = getenv("MONGOADMINUSER")         //共享实例和独立实例的管理员用户名
	mongoAdminPassword = getenv("MONGOADMINPASSWORD") //共享实例和独立实例的管理员密码
	mongoDashboard = getenv("MONGODASHBOARD")         //dashboard的目标地址
}
