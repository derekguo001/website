---
title: "第二章 ServiceController源代码解析"
linkTitle: "第二章 ServiceController"
weight: 2
date: 2017-01-04
description: >
---

{{< figure src="../servicecontroller_data_1.png" link="../servicecontroller_data_1.png" target="_blank" >}}

## 一、模型定义 ##

### 抽象模型定义 ###

pilot discovery内部维护了一套自己的数据结构，外部的对象被同步到pilot discovery内部后会转换成内部的数据结构，当外部的对象更新后，也会自动更新内部的这些对象。当需要向envoy推送配置的时候，会从内部的这些对象转化成envoy格式的配置。

其中最基本的有三类：Service、Port和IstioEndpoint，都在model模块中定义。大致上可以认为是kubernetes中的service、pod和endpoint在pilot discovery内部的格式。当读取外部的kube service和endpoint后会进行一些格式转换，转换成内部的这些对象。

在这三类基本对象的基础上进行了一些聚合，形成了另一个抽象的对象ServiceInstance

```
type ServiceInstance struct {
	Service     *Service       `json:"service,omitempty"`
	ServicePort *Port          `json:"servicePort,omitempty"`
	Endpoint    *IstioEndpoint `json:"endpoint,omitempty"`
}
```

为了管理这些对象(主要是Service和ServiceInstance)，定义了两个Interface

1. Controller

    ```
    type Controller interface {
        AppendServiceHandler(f func(*Service, Event)) error
        AppendInstanceHandler(f func(*ServiceInstance, Event)) error
        Run(stop <-chan struct{})
        HasSynced() bool
    }
    ```

    可以看出这是一个可以Run()的实体对象

    - 在pilot discovery后续进行初始化的时候，会调用这里的这两个append函数注册一些回调函数
    - envoy连接后会向Controller注册自己
    - 当Service和ServiceInstance发生变化的时候，Controller会调用之前注册的回调函数向envoy推送更新后的配置

2. ServiceDiscovery

   ```
   type ServiceDiscovery interface {
       Services() ([]*Service, error)
       GetService(hostname host.Name) (*Service, error)
       InstancesByPort(svc *Service, servicePort int, labels labels.Collection) ([]*ServiceInstance, error)
       GetProxyServiceInstances(*Proxy) ([]*ServiceInstance, error)
       GetProxyWorkloadLabels(*Proxy) (labels.Collection, error)
       ManagementPorts(addr string) PortList
       WorkloadHealthCheckInfo(addr string) ProbeList
       GetIstioServiceAccounts(svc *Service, ports []int) []string
   }
   ```

   相对于上面的Controller，这里的ServiceDiscovery没有Run()这些函数，它更像是一个静态的对象，它的作用就是用来获取目前存在的内部对象，包括Service和Instance等。

   这些抽象模型的定义位于`pilot/pkg/model`中。

### 抽象模型的实例化 ###

在第一部分定义的两个Interface(Controller和ServiceDiscovery)的基础上，pilot discovery需要将这些东西实例化，要落实到某种具体的对象上，比如kubernetes。这些实例化的对象被称为serviceregistry，代码位于`pilot/pkg/serviceregistry`。

首先，定义了一个Instance接口，注意它完全不同于上文提到的ServiceInstance，它们是完全不相关的两个东西。

```
type Instance interface {
	model.Controller
	model.ServiceDiscovery

	// Provider backing this service registry (i.e. Kubernetes, Consul, etc.)
	Provider() ProviderID

	// Cluster for which the service registry applies. Only needed for multicluster systems.
	Cluster() string
}
```

可以看出，Instance继承了上文中的`model.Controller`和`model.ServiceDiscovery`，也就意味着我们可以通过Instance实例可以操纵所有上文中提到的对象，主要是`model.Service`和`model.ServiceInstance`。

接下来看`Provider()`，它的返回值是一个字符串，实际上就是某一种实现的具体类型。

```
// ProviderID defines underlying platform supporting service registry
type ProviderID string

const (
	// Mock is a service registry that contains 2 hard-coded test services
	Mock ProviderID = "Mock"
	// Kubernetes is a service registry backed by k8s API server
	Kubernetes ProviderID = "Kubernetes"
	// Consul is a service registry backed by Consul
	Consul ProviderID = "Consul"
	// MCP is a service registry backed by MCP ServiceEntries
	MCP ProviderID = "MCP"
	// External is a service registry for externally provided ServiceEntries
	External = "External"
)
```

pilot discovery定义了Instance接口作为某一种具体实现的父类，具体的实现都需要继承Instance并实现其中的接口。具体的实现包括Kubernetes、Consul、MCP、External等。其中的MCP是为了进一步解耦Istio与Kubernetes而开发的一个新的抽象层，暂时可以不需要太关注。目前我们仍然直接与Kubernetes进行对接。另外External是用来对接外部的一些服务而开发的一套实现。

由于有这么多具体的实现，为了对它们进行统一管理，pilot discovery又定义了另外一个对象serviceregistry.aggregate.Controller。
代码在`pilot/pkg/serviceregistry/aggregate`中。

```
type Controller struct {
	registries []serviceregistry.Instance
	storeLock  sync.RWMutex
}
```

它里面的`registries`就是具体实现的serviceregistry的数组。

这个Controller并没有直接继承上文中的Instance接口，因为它不是某一类具体的实现。它实现了Instance接口的两个父接口(Controller和ServiceDiscovery)。实现Controller和ServiceDiscovery这两个父接口的方式，也是分别遍历内部的`registries`数组，然后针对每一个具体的实现调用对应的函数。

例如下面是对应于ServiceDiscovery Interface的`Services() ([]*Service, error)`的实现

```
func (c *Controller) Services() ([]*model.Service, error) {
    ...
	services := make([]*model.Service, 0)

	for _, r := range c.GetRegistries() {
		svcs, err := r.Services()
        ...
			services = append(services, svcs...)
        ...
		}
	}
	return services, errs
}
```

可以看出serviceregistry.aggregate.Controller的实现方式，就是通过`GetRegistries()`遍历内部的`registries`数组，然后针对每一个具体的实现调用对应的`Services()`，然后将结果聚合到一起返回。

下面通过分析一下相关组件的启动过程来看一些上面的这些对象和操作是如何在Istio pilot discovery中关联起来的。

## 二、启动过程分析 ##

### 模型定义 ###

Istio pilot discovery有一个总的Server对象

```
type Server struct {
    ...
	environment *model.Environment
	kubeRegistry *kubecontroller.Controller
	serviceEntryStore *serviceentry.ServiceEntryStore
    ...
}
```

和ServiceController相关的有三个成员。其中kubeRegistry和serviceEntryStore实际上就是ServiceController对应于Kubernetes和外部服务的实例化对象。

另外一个是environment成员

```
type Environment struct {
	ServiceDiscovery
    ...
}
```

它里面的ServiceDiscovery成员就是上文中提到的serviceregistry.aggregate.Controller。

这里可以总结一下，当ServiceController对象实例化之后，产生了很多实例对象，包括kubernetes、mcp、external等等，这些controller聚合到一起形成了serviceregistry.aggregate.Controller对象，这个对象本身作为Environment的ServiceDiscovery成员存储于Environment中，而Environment本身又作为pilot discovery的Server对象中的environment成员。这是ServiceController对象实例与pilot discovery的Server对象的第一个关联点。

另外，刚才生成提到的ServiceController对象实例化之后，产生了很多实例对象，包括kubernetes、mcp、external，其中的kubernetes和external又直接存储到了pilot discovery的Server对象中，对应的成员名为kubeRegistry和serviceEntryStore。这是ServiceController对象实例与pilot discovery的Server对象的第二个关联点。

### 初始化 ###

main函数位于`pilot/cmd/pilot-discovery/main.go`中

```
var (
    ...
	discoveryCmd = &cobra.Command{
		Use:   "discovery",
		Short: "Start Istio proxy discovery service.",
		Args:  cobra.ExactArgs(0),
		RunE: func(c *cobra.Command, args []string) error {
			discoveryServer, err := bootstrap.NewServer(serverArgs)
            ...
			if err := discoveryServer.Start(stop); err != nil {
				return fmt.Errorf("failed to start discovery service: %v", err)
			}
            ...
		},
	}
)


func init() {
    ...
	rootCmd.AddCommand(discoveryCmd)
    ...
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(-1)
	}
}

```

初始化代码位于`bootstrap.NewServer(serverArgs)`中

`pilot/pkg/bootstrap/server.go`

```
func NewServer(args *PilotArgs) (*Server, error) {
	e := &model.Environment{
		ServiceDiscovery: aggregate.NewController(),
		PushContext:      model.NewPushContext(),
		DomainSuffix:     args.Config.ControllerOptions.DomainSuffix,
	}
	s := &Server{
        ...
		environment:     e,
        ...
	}
```

先创建Environment对象并将其存到Server中，执行时会在Environment内创建一个空的serviceregistry.aggregate.Controller，但还未向里面添加ServiceController实例，代码如下

```
// NewController creates a new Aggregate controller
func NewController() *Controller {
	return &Controller{
		registries: make([]serviceregistry.Instance, 0),
	}
}
```

创建了Server对象后，会进行初始化，在`initControllers()`中

```
func NewServer(args *PilotArgs) (*Server, error) {
	e := &model.Environment{
		ServiceDiscovery: aggregate.NewController(),
		PushContext:      model.NewPushContext(),
		DomainSuffix:     args.Config.ControllerOptions.DomainSuffix,
	}
	s := &Server{
        ...
		environment:     e,
        ...
	}

    ...
	if err := s.initControllers(args); err != nil {
		return nil, err
	}
}

func (s *Server) initControllers(args *PilotArgs) error {
    ...
	if err := s.initServiceControllers(args); err != nil {
		return fmt.Errorf("error initializing service controllers: %v", err)
	}
	return nil
}
```

下面详细分析`initServiceControllers()`

```
func (s *Server) initServiceControllers(args *PilotArgs) error {
	serviceControllers := s.ServiceController()
	registered := make(map[serviceregistry.ProviderID]bool)
	for _, r := range args.Service.Registries {
		serviceRegistry := serviceregistry.ProviderID(r)
		if _, exists := registered[serviceRegistry]; exists {
			log.Warnf("%s registry specified multiple times.", r)
			continue
		}
		registered[serviceRegistry] = true
		log.Infof("Adding %s registry adapter", serviceRegistry)
		switch serviceRegistry {
		case serviceregistry.Kubernetes:
			if err := s.initKubeRegistry(serviceControllers, args); err != nil {
				return err
			}
		case serviceregistry.Consul:
			if err := s.initConsulRegistry(serviceControllers, args); err != nil {
				return err
			}
		case serviceregistry.Mock:
			s.initMockRegistry(serviceControllers)
		default:
			return fmt.Errorf("service registry %s is not supported", r)
		}
	}

	s.serviceEntryStore = serviceentry.NewServiceDiscovery(s.configController, s.environment.IstioConfigStore, s.EnvoyXdsServer)
	serviceControllers.AddRegistry(s.serviceEntryStore)

    ...

	// Defer running of the service controllers.
	s.addStartFunc(func(stop <-chan struct{}) error {
		go serviceControllers.Run(stop)
		return nil
	})

	return nil
}
```

这个函数首先用`serviceControllers := s.ServiceController()`来获取Environment中serviceregistry.aggregate.Controller，这个对象在刚才已经被初始化，且它内部的registries数组为空。

接下来根据用户配置创建不同种类的ServiceController并将其添加到Environment中serviceregistry.aggregate.Controller的registries数组中。

例如s.serviceEntryStore存储了ServiceController对应于外部服务的实例化对象，同时也将其加入了Environment中serviceregistry.aggregate.Controller的registries数组。

下面kubernetes为例再详细分析，来看`initKubeRegistry()`

```
func (s *Server) initKubeRegistry(serviceControllers *aggregate.Controller, args *PilotArgs) (err error) {
    ...
	kubeRegistry := kubecontroller.NewController(s.kubeClient, s.metadataClient, args.Config.ControllerOptions)
	s.kubeRegistry = kubeRegistry
	serviceControllers.AddRegistry(kubeRegistry)
	return
}

func (c *Controller) AddRegistry(registry serviceregistry.Instance) {
	c.storeLock.Lock()
	defer c.storeLock.Unlock()

	registries := c.registries
	registries = append(registries, registry)
	c.registries = registries
}

```

`kubecontroller.NewController()`返回一个Kubernetes的ServiceController实例，然后将其添加到第一个参数`serviceControllers`的`registries`数组中。这里的`serviceControllers`也就是上文中提到的Environment中serviceregistry.aggregate.Controller。这是ServiceController对象实例与pilot discovery的Server对象的第一个关联点。

另外，`s.kubeRegistry = kubeRegistry`同时也将Kubernetes的ServiceController实例存到pilot discovery的Server的`kubeRegistry`字段中，这就是上面提到的ServiceController对象实例与pilot discovery的Server对象的第二个关联点。

这些ServiceController运行后会在内部watch各自的资源，但是截至目前为止也仅仅是watch，还未与pilot discovery server其他组件没有发生关联，下面会看到在后面的初始化过程中会注册一下回调函数。

### 注册回调函数 ###

```
func NewServer(args *PilotArgs) (*Server, error) {
	e := &model.Environment{
		ServiceDiscovery: aggregate.NewController(),
		PushContext:      model.NewPushContext(),
		DomainSuffix:     args.Config.ControllerOptions.DomainSuffix,
	}

	s := &Server{
		clusterID:       getClusterID(args),
		environment:     e,
        ...
	}

    ...

	if err := s.initControllers(args); err != nil {
		return nil, err
	}

    ...
	if err := s.initRegistryEventHandlers(); err != nil {
		return nil, fmt.Errorf("error initializing handlers: %v", err)
	}
    ...

	return s, nil
}
```

注册回调函数的代码在`initRegistryEventHandlers()`


```
// initRegistryEventHandlers sets up event handlers for config and service updates
func (s *Server) initRegistryEventHandlers() error {
	// Flush cached discovery responses whenever services configuration change.
	serviceHandler := func(svc *model.Service, _ model.Event) {
		pushReq := &model.PushRequest{
			Full: true,
			ConfigsUpdated: map[model.ConfigKey]struct{}{{
				Kind:      model.ServiceEntryKind,
				Name:      string(svc.Hostname),
				Namespace: svc.Attributes.Namespace,
			}: {}},
			Reason: []model.TriggerReason{model.ServiceUpdate},
		}
		s.EnvoyXdsServer.ConfigUpdate(pushReq)
	}
	if err := s.ServiceController().AppendServiceHandler(serviceHandler); err != nil {
		return fmt.Errorf("append service handler failed: %v", err)
	}

    ...

	return nil
}
```


这里使用`serviceregistry.aggregate.Controller.AppendServiceHandler()`注册了处理Service的回调函数。

```
// AppendServiceHandler implements a service catalog operation
func (c *Controller) AppendServiceHandler(f func(*model.Service, model.Event)) error {
	for _, r := range c.GetRegistries() {
		if err := r.AppendServiceHandler(f); err != nil {
			log.Infof("Fail to append service handler to adapter %s", r.Provider())
			return err
		}
	}
	return nil
}
```

而在`serviceregistry.aggregate.Controller.AppendServiceHandler()`内部，则会调用每一个实际的ServiceController实例来把回调函数注册到每个ServiceController实例中。

例如kubernetes的ServiceController，将这些回调函数注册到自身实例中后，会在watch到相关资源改变的情况下，来调用这些预先注册的回调函数做实际的事情。

比如上面的这个回调函数的内容

```
	serviceHandler := func(svc *model.Service, _ model.Event) {
		pushReq := &model.PushRequest{
			Full: true,
			ConfigsUpdated: map[model.ConfigKey]struct{}{{
				Kind:      model.ServiceEntryKind,
				Name:      string(svc.Hostname),
				Namespace: svc.Attributes.Namespace,
			}: {}},
			Reason: []model.TriggerReason{model.ServiceUpdate},
		}
		s.EnvoyXdsServer.ConfigUpdate(pushReq)
	}
```

就是构造一个push请求，然后将其作为参数来更新与envoy通信的discovery server，后者会更新配置并将配置推送给envoy，详细的内容请见后续的文章。
