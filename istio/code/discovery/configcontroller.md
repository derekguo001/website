---
title: "第三章 ConfigController源代码解析"
linkTitle: "第三章 ConfigController"
weight: 3
date: 2017-01-04
description: >
---

{{< figure src="../configcontroller_data_1.png" link="../configcontroller_data_1.png" target="_blank" >}}

## 一、对象模型 ##

### 具体的对象模型 ###

Istio中有一些新定义的对象模型，例如VirtualService、DestinationRule等等，它们在kubernetes中作为crd对象存在，它们在Istio中被统称为config，为了管理这些crd对象，Istio内部定义一些controller，被称为ConfigController，除了管理crd对象外，还有一些管理其它对象的ConfigController。具体而言，管理crd对象的ConfigController被称为crd ConfigController，或者简称为crd controller，代码位于`pilot/pkg/config/kube/crd`

Envoy除了作为sidecar之外，还可以作为ingress网关，用作整个集群的入口，这种情况下它的工作模式不同于sidecar模式，因此需要另外定义另一种ConfigController来对这种模式下的对象模型进行管理，它们被称为ingress ConfigController，代码位于`pilot/pkg/config/kube/ingress`

为了方便调试，又开发了基于内存的controller，被称为memory ConfigController，代码位于`pilot/pkg/config/memory`

上面提到的crd controller和ingress controller直接与kubernetes交互，为了解耦Istio与Kubernetes，又开发了一个新的抽象层，被称为mcp controller。代码位于`pilot/pkg/serviceregistry/mcp`，注意它与上面的几个controller都不在同一个目录下，这是因为mcp controller不仅实现了ConfigController的功能，同时也实现了ServiceController的功能，详见上一节的内容。

### 具体对象模型的抽象父接口 ###

这些具体的ConfigController有2个共同的父接口，被称为model.ConfigStore和model.ConfigSotreCache，其中ConfigStore可以认为是一个静态的接口，可以通过这个接口中的函数来对config对象进行增删改查，其中有一个`Schemas`字段，包含了所有的原始对象。ConfigStore的定义如下

``` golang
type ConfigStore interface {
	Schemas() collection.Schemas

	Get(typ resource.GroupVersionKind, name, namespace string) *Config
	List(typ resource.GroupVersionKind, namespace string) ([]Config, error)
	Create(config Config) (revision string, err error)
	Update(config Config) (newRevision string, err error)
	Delete(typ resource.GroupVersionKind, name, namespace string) error
    ...
}
```

而另一个对象ConfigSotreCache相对于ConfigStore而言，是一个动态的接口，定义如下

``` golang
type ConfigStoreCache interface {
	ConfigStore

	RegisterEventHandler(kind resource.GroupVersionKind, handler func(Config, Config, Event))
	Run(stop <-chan struct{})
	HasSynced() bool
}
```

首先，它继承了ConfigStore，另外它定义了`Run()`表明它是可以作为一个动态对象来Run，它还定义了一个`RegisterEventHandler()`函数，用来添加一些回调函数，当config发生改变的时候会触发这些回调函数。

除了这两个Interface之外，还有一个名为IstioConfigStore的Interface，它主要用于获取外部服务的相关信息，我们不会对其进行详细分析，定义如下

``` golang
type IstioConfigStore interface {
	ConfigStore
	ServiceEntries() []Config
	Gateways(workloadLabels labels.Collection) []Config
    ...
}
```

### 聚合对象 ###

现在回到上文提到的具体的ConfigController的实现，包括ingress controller、crd controller、mcp controller等，为了对它们进行统一管理，创建了两个新的聚合controller。代码都位于`pilot/pkg/config/aggregate`

其中第一个聚合对象叫store

``` golang
type store struct {
	schemas collection.Schemas
	stores map[resource.GroupVersionKind][]model.ConfigStore
    ...
}
```

一方面它内部包含有schemas字段，用来存储原始对象，还包含一个stores字段，这是一个map，用来分类存储各种ConfigStore对象。另一方面它继承了上文提到的model.ConfigStore接口，也就意味着当对这个store执行model.ConfigStore接口里的函数时，store会遍历自己内部存储的各种具体的ConfigController对象，分别对他们对应的操作，来看一个例子

``` golang
// List all configs in the stores.
func (cr *store) List(typ resource.GroupVersionKind, namespace string) ([]model.Config, error) {
    ...
	configMap := make(map[string]struct{})

	for _, store := range cr.stores[typ] {
		storeConfigs, err := store.List(typ, namespace)
        ...
		for _, config := range storeConfigs {
			key := config.Type + config.Namespace + config.Name
			if _, exist := configMap[key]; exist {
				continue
			}
			configs = append(configs, config)
			configMap[key] = struct{}{}
		}
	}
	return configs, errs.ErrorOrNil()
}
```

这是store继承并实现的model.ConfigStore接口中的List()函数，可以看出它就是遍历内部的各种ConfigController对象，然后在内部将各种config对象聚合到一起然后返回。

第二个聚合对象叫storeCache

``` golang
type storeCache struct {
	model.ConfigStore
	caches []model.ConfigStoreCache
}
```

它有一个caches数组，里面包含了具体的各种ConfigController对象(因为它们都实现了ConfigStoreCache Interface)。另一方面storeCache实现了model.ConfigStoreCache Interface。当执行对这个storeCache对象执行model.ConfigStoreCache接口里的函数时，storeCache会遍历自己内部存储的各种具体的ConfigController对象，分别对他们对应的操作，下面是`RegisterEventHandler()`的实现

``` golang
func (cr *storeCache) RegisterEventHandler(kind resource.GroupVersionKind, handler func(model.Config, model.Config, model.Event)) {
	for _, cache := range cr.caches {
		if _, exists := cache.Schemas().FindByGroupVersionKind(kind); exists {
			cache.RegisterEventHandler(kind, handler)
		}
	}
}
```

可以看到这个函数的逻辑就是遍历内部的cache数组，然后针对每个具体的ConfigController对象执行`RegisterEventHandler()`调用。

## 二、启动过程分析 ##

### 模型定义 ###

Istio pilot discovery有一个总的Server对象

``` golang
type Server struct {
    ...
	environment *model.Environment

	configController  model.ConfigStoreCache

	ConfigStores      []model.ConfigStoreCache
    ...
}
```

和ConfigController相关的有三个成员。其中Server.ConfigStores就是各种ConfigController实例组成一个数组，而Server.configController就是config.aggregate.storeCache的实例，内部包含了Server.ConfigStores对象。

另外一个是environment成员

``` golang
type Environment struct {
	IstioConfigStore
    ...
}
```

它里面的IstioConfigStore成员就是上文中提到的model.IstioConfigStore，主要用于获取外部服务等信息。

### 初始化 ###

main函数位于`pilot/cmd/pilot-discovery/main.go`中

``` golang
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

创建了Server对象后，会进行初始化，在`initControllers()`中

``` golang
func NewServer(args *PilotArgs) (*Server, error) {
    ...
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
	if err := s.initConfigController(args); err != nil {
		return fmt.Errorf("error initializing config controller: %v", err)
	}
	return nil
}
```

下面详细分析`initConfigController()`

``` golang
func (s *Server) initConfigController(args *PilotArgs) error {
	meshConfig := s.environment.Mesh()
	if len(meshConfig.ConfigSources) > 0 {
		if err := s.initMCPConfigController(args); err != nil {
			return err
		}
	} else if args.Config.FileDir != "" {
		store := memory.Make(collections.Pilot)
		configController := memory.NewController(store)
		s.ConfigStores = append(s.ConfigStores, configController)
	} else {
		configController, err := s.makeKubeConfigController(args)
        ...
		s.ConfigStores = append(s.ConfigStores, configController)
        ...
	}
    ...
```

这个函数首先用根据配置来创建不同的ConfigController：MCP Controller(如果符合这个条件，则创建后会立即返回)、Memery Controller和Kubernetes Controller。然后controller加到Server.ConfigStores中

``` golang
	if hasKubeRegistry(args.Service.Registries) && meshConfig.IngressControllerMode != meshconfig.MeshConfig_OFF {
		s.ConfigStores = append(s.ConfigStores,
			ingress.NewController(s.kubeClient, meshConfig, args.Config.ControllerOptions))
        ...
	}
```

接下来如果启用了ingress模式，则会将Ingress Controller也加入Server.ConfigStores中。

``` golang
	aggregateConfigController, err := configaggregate.MakeCache(s.ConfigStores)
	if err != nil {
		return err
	}
	s.configController = aggregateConfigController

	// Create the config store.
	s.environment.IstioConfigStore = model.MakeIstioStore(s.configController)

	// Defer starting the controller until after the service is created.
	s.addStartFunc(func(stop <-chan struct{}) error {
		go s.configController.Run(stop)
		return nil
	})

	return nil
}
```

最后会根据Server.ConfigStores生成Server.configController，这个在上面分析过，就是config.aggregate.storeCache的实例。

最后会添加启动的回调函数，当Server启动时也会启动Server.configController。

### 注册回调函数 ###

``` golang
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

``` golang
// initRegistryEventHandlers sets up event handlers for config and service updates
func (s *Server) initRegistryEventHandlers() error {
    ...

	if s.configController != nil {
		configHandler := func(_, curr model.Config, event model.Event) {
			pushReq := &model.PushRequest{
				Full: true,
				ConfigsUpdated: map[model.ConfigKey]struct{}{{
					Kind:      curr.GroupVersionKind(),
					Name:      curr.Name,
					Namespace: curr.Namespace,
				}: {}},
				Reason: []model.TriggerReason{model.ConfigUpdate},
			}
			s.EnvoyXdsServer.ConfigUpdate(pushReq)
            ...
		}
		schemas := collections.Pilot.All()
        ...
		for _, schema := range schemas {
            ...
			s.configController.RegisterEventHandler(schema.Resource().GroupVersionKind(), configHandler)
		}
	}

	return nil
}
```

这里使用`config.aggregate.storeCache.RegisterEventHandler()`注册了处理Config的回调函数。

``` golang
func (cr *storeCache) RegisterEventHandler(kind resource.GroupVersionKind, handler func(model.Config, model.Config, model.Event)) {
	for _, cache := range cr.caches {
		if _, exists := cache.Schemas().FindByGroupVersionKind(kind); exists {
			cache.RegisterEventHandler(kind, handler)
		}
	}
}
```

这部分上面看过，就是会遍历自己内部存储的各种具体的ConfigController对象，分别调用它们的对应接口把回调函数注册到每个ConfigController实例中。

例如kubernetes crd config controller，将这些回调函数注册到自身实例中后，会在watch到相关资源改变的情况下，来调用这些预先注册的回调函数做实际的事情。

比如上面的这个回调函数就是构造一个push请求，然后将其作为参数来更新与envoy通信的discovery server，后者会更新配置并将配置推送给envoy，详细的内容请见后续的文章。
