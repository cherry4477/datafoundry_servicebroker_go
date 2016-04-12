package handler

import (
	"encoding/base64"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pivotal-cf/brokerapi"
	"gopkg.in/mgo.v2"
	"strings"
)

const (
	awsRegion      string = "cn-north-1"
	imageId        string = "ami-b18942dc"
	instanceType   string = "t2.micro"
	keyName        string = "service_borker"
	securityGroups string = "service borker"
)

type Mongodb_aws_standaloneHandler struct{}

func (handler *Mongodb_aws_standaloneHandler) DoProvision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, ServiceInfo, error) {
	//需要有两个环境变量 AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

	//todo需要检查参数，如果不允许异步，那么要给客户端报错的

	//初始化aws client
	svc := ec2.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))
	//准备管理用户名和密码
	newusername := getguid()
	newpassword := getguid()
	//拼接启动aws实例用的userdata
	//userdate sample
	//#!/bin/bash
	//mongo <<!!!
	//use admin
	//db.auth('asiainfoLDP','6ED9BA74-75FD-4D1B-8916-842CB936AC1A');
	//db.createUser({ user: 'test', pwd: 'test', roles: [ { role: 'root', db: 'admin' } ] });
	//!!!

	userdata := "#!/bin/bash \n mongo <<!!! \n use admin \n db.auth('" + mongoAdminUser + "','" + mongoAdminPassword + "'); \n db.createUser({ user: '" + newusername + "', pwd: '" + newpassword + "', roles: [ { role: 'root', db: 'admin' } ] }); \n !!!"
	// Specify the details of the instance that you want to create.
	runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
		ImageId:        aws.String(imageId),
		InstanceType:   aws.String(instanceType),
		KeyName:        aws.String(keyName),
		SecurityGroups: []*string{aws.String(securityGroups)},
		MinCount:       aws.Int64(1),
		MaxCount:       aws.Int64(1),
		UserData:       aws.String(base64.StdEncoding.EncodeToString([]byte(userdata))),
	})

	if err != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	awsmongourl := *runResult.Instances[0].PrivateIpAddress + ":27017"

	// Add tags to the created instance
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{runResult.Instances[0].InstanceId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String("service_mongodb_" + *runResult.Instances[0].InstanceId),
			},
		},
	})
	if errtag != nil {
		return brokerapi.ProvisionedServiceSpec{}, ServiceInfo{}, err
	}

	//赋值隐藏属性
	myServiceInfo := ServiceInfo{
		Url:            *runResult.Instances[0].InstanceId, //aws的实例id
		Admin_user:     mongoAdminUser,
		Admin_password: mongoAdminPassword,
		Database:       "admin",
		User:           newusername,
		Password:       newpassword,
	}

	//为dashbord赋值 todo dashboard应该提供一个界面才对
	//todo 没有公网地址
	DashboardURL := "http://" + strings.Split(awsmongourl, ":")[0] + "/index.php?action=autologin.index&user=" + newusername + "&pass=" + newpassword

	//表示是异步返回
	provsiondetail := brokerapi.ProvisionedServiceSpec{DashboardURL: DashboardURL, IsAsync: true}

	return provsiondetail, myServiceInfo, nil
}

func (handler *Mongodb_aws_standaloneHandler) DoLastOperation(myServiceInfo *ServiceInfo) (brokerapi.LastOperation, error) {
	//定义返回值
	var lastOperation brokerapi.LastOperation
	//初始化aws client
	svc := ec2.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))
	//从service_instance的etcd目录中取出aws instance的id，以便查询
	awsInstaceID := myServiceInfo.Url
	//查询实例
	runResult, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(awsInstaceID), // Required
			// More values...
		},
	})

	//出错后显示出错
	if err != nil {
		return brokerapi.LastOperation{}, err
	}

	//注意：由于service_broker.go中并没有像规范里面一样定义410 gone这个状态，因此，暂时不对update和deporivion返回 to
	if len(runResult.Reservations) == 0 {
		return brokerapi.LastOperation{}, errors.New("aws instance status not exist " + awsInstaceID)
	}

	switch *runResult.Reservations[0].Instances[0].State.Name {
	case "pending":
		lastOperation = brokerapi.LastOperation{
			State:       brokerapi.InProgress,
			Description: "creating service instance " + awsInstaceID,
		}
	case "running":
		lastOperation = brokerapi.LastOperation{
			State:       brokerapi.Succeeded,
			Description: "successfully created service instance " + awsInstaceID,
		}
	default:
		lastOperation = brokerapi.LastOperation{
			State:       brokerapi.Failed,
			Description: "failed to create service instance " + awsInstaceID,
		}
	}
	return lastOperation, nil
}

func (handler *Mongodb_aws_standaloneHandler) DoDeprovision(myServiceInfo *ServiceInfo, asyncAllowed bool) (brokerapi.IsAsync, error) {
	//初始化aws client
	svc := ec2.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))
	//从service_instance的etcd目录中取出aws instance的id，以便查询
	awsInstaceID := myServiceInfo.Url
	//查询实例
	runResult, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(awsInstaceID), // Required
			// More values...
		},
	})

	//出错后显示出错
	if err != nil {
		return brokerapi.IsAsync(false), err
	}

	//没有找到任何aws的实例
	if len(runResult.Reservations) == 0 {
		return brokerapi.IsAsync(false), errors.New("aws instance status not exist " + awsInstaceID)
	}

	if *runResult.Reservations[0].Instances[0].State.Name == "running" {
		//可以删除的状态

		//开始删除实例
		_, err := svc.TerminateInstances(&ec2.TerminateInstancesInput{
			InstanceIds: []*string{
				aws.String(awsInstaceID), // Required
				// More values...
			},
		})

		if err != nil {
			return brokerapi.IsAsync(false), err
		}
	} else {
		return brokerapi.IsAsync(false), errors.New("Another operation for this service instance is in progress")
	}

	//非异步，无错误的返回
	return brokerapi.IsAsync(false), nil
}

func (handler *Mongodb_aws_standaloneHandler) DoBind(myServiceInfo *ServiceInfo, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, Credentials, error) {
	//初始化aws client
	svc := ec2.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))
	//从service_instance的etcd目录中取出aws instance的id，以便查询
	awsInstaceID := myServiceInfo.Url
	//查询实例
	runResult, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(awsInstaceID), // Required
			// More values...
		},
	})

	//出错后显示出错
	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}

	//没有找到任何aws的实例
	if len(runResult.Reservations) == 0 {
		return brokerapi.Binding{}, Credentials{}, errors.New("aws instance status not exist " + awsInstaceID)
	}

	var mongodburl, mongodbname string
	var mongodbrole mgo.Role

	if *runResult.Reservations[0].Instances[0].State.Name == "running" {
		//可以绑定的状态
		//暂时利用公网地址，以后都部署在一个云平台上和一个安全域内部的话，可以使用私网地址
		mongodburl = *runResult.Reservations[0].Instances[0].PublicIpAddress + ":27017"
		//对于standalone的情况，应该创建一个dbadmin on any database的角色，所以数据库应该是admin
		mongodbname = "admin"
		//角色
		mongodbrole = mgo.RoleDBAdminAny
	} else {
		//不可以执行的状态，反馈400，但是目前servie_broker的包里面没有这个状态的判断，只有暂时返回500 todo
		return brokerapi.Binding{}, Credentials{}, errors.New("Another operation for this service instance is in progress")
	}

	//完成变量赋值以后，开始准备创建用户
	//初始化mongodb的链接串
	session, err := mgo.Dial(mongodburl) //连接数据库
	if err != nil {
		return brokerapi.Binding{}, Credentials{}, err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	mongodb := session.DB("admin") //数据库名称
	err = mongodb.Login(myServiceInfo.Admin_user, myServiceInfo.Admin_password)
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
		Uri:      "mongodb://" + newusername + ":" + newpassword + "@" + mongodburl,
		Hostname: strings.Split(mongodburl, ":")[0],
		Port:     strings.Split(mongodburl, ":")[1],
		Username: newusername,
		Password: newpassword,
	}

	myBinding := brokerapi.Binding{Credentials: mycredentials}

	return myBinding, mycredentials, nil
}

func (handler *Mongodb_aws_standaloneHandler) DoUnbind(myServiceInfo *ServiceInfo, mycredentials *Credentials) error {
	var mongodburl string
	var mongodbname string
	//初始化aws client
	svc := ec2.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))
	//从service_instance的etcd目录中取出aws instance的id，以便查询
	awsInstaceID := myServiceInfo.Url
	//查询实例
	runResult, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(awsInstaceID), // Required
			// More values...
		},
	})

	//出错后显示出错
	if err != nil {
		return err
	}

	//没有找到任何aws的实例
	if len(runResult.Reservations) == 0 {
		return errors.New("aws instance status not exist " + awsInstaceID)
	}

	if *runResult.Reservations[0].Instances[0].State.Name == "running" {
		//可以解除绑定的状态
		//暂时利用公网地址，以后都部署在一个云平台上和一个安全域内部的话，可以使用私网地址
		mongodburl = *runResult.Reservations[0].Instances[0].PublicIpAddress + ":27017"
		//对于standalone的情况，应该创建一个dbadmin on any database的角色，所以数据库应该是admin
		mongodbname = "admin"
	} else {
		return errors.New("Another operation for this service instance is in progress")
	}

	//初始化mongodb的链接串
	session, err := mgo.Dial(mongodburl) //连接数据库
	if err != nil {
		return err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	mongodb := session.DB("admin") //数据库名称
	err = mongodb.Login(myServiceInfo.Admin_user, myServiceInfo.Admin_password)
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
	register("mongodb_aws_standalone", &Mongodb_aws_standaloneHandler{})
}
