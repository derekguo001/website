---
title: "第四章 DiscoveryServer源代码解析"
linkTitle: "第四章 DiscoveryServer"
weight: 4
date: 2017-01-04
description: >
---

## 一、数据结构 ##

{{< figure src="../discoveryserver_data_1.png" link="../discoveryserver_data_1.png" target="_blank" >}}

本节主要关注pilot discovery与envoy交互部分。

### DiscoveryServer相关的数据结构 ###

pilot discovery的服务器server对象包含一个名为DiscoveryServer组件，存储这个对象的字段名为EnvoyXdsServer，见下面的定义

```
// Server contains the runtime configuration for the Pilot discovery service.
type Server struct {
    ...
	EnvoyXdsServer *envoyv2.DiscoveryServer
	environment *model.Environment

    ...
}
```

为了避免混淆，下面将pilot discovery的server称为`server`，而它内部的`EnvoyXdsServer *envoyv2.DiscoveryServer`对象则称为`DiscoveryServer`。

而这个DiscoveryServer的作用就是用来与envoy通信。它实现了两个接口

1. `go_control_plane.envoy.service.discovery.v2.AggregatedDiscoveryServiceServer`

   这个接口定义了当envoy proxy向server主动发起请求时server如何进行相应

2. `model.XDSUpdater`

   这个接口定义了当server发现配置信息(包括kube svc、istio crd等)修改了之后主动向envoy proxy推送消息的功能

### 与Envoy proxy交互时涉及到的数据结构 ###

这些对象按照范围可以分成两类：全局的对象、属于某个envoy proxy的局部对象

- PushContext

  全局对象，包含了当前DiscoveryServer中所有的Service和CRD对象以及一些其它对象，也就意味着所有envoy proxy相关的数据都统一存储在这里，在针对某个具体的envoy proxy处理的时候会进行解析和过滤，进一步提取特定的信息。

- XdsConnection

  局部变量，表示与某个envoy proxy连接的对象，当envoy proxy向DiscoveryServer发起连接时建立。

- DiscoveryRequest

  `envoy/api/v2/discovery.proto`

  局部对象，表示每一个envoy proxy发起的请求的详情，比如envoy proxy会请求cluster、listener等资源。

- Node

  `envoy/api/envoy/api/v2/core/base.proto`

  局部对象，表示每一个envoy proxy本身，里面包含有这个envoy proxy的ID、元数据等一些信息

- Proxy

  局部对象，与`Node`作用类似，也是包含envoy proxy对象的信息，但是这里保存的是经过处理后的的信息，相对于`Node`对象，使用起来会方便很多

- SidecarScope

  局部对象，用来表示当前envoy proxy的作用范围

在下一节中可以看到这些对象相互的关系以及它们是如何初始化的。

## 二、DiscoveryServer创建过程 ##

当创建server时，首先会创建一个Environment对象，并将其存储在server中。接下来它会用Environment作为第一个参数来创建DiscoveryServer对象。

```
func NewServer(args *PilotArgs) (*Server, error) {
	e := &model.Environment{
		ServiceDiscovery: aggregate.NewController(),
		PushContext:      model.NewPushContext(),
	}

	s := &Server{
		clusterID:      getClusterID(args),
		environment:    e,
		EnvoyXdsServer: envoyv2.NewDiscoveryServer(e, args.Plugins),
		forceStop:      args.ForceStop,
		mux:            http.NewServeMux(),
	}
```

```
func NewDiscoveryServer(env *model.Environment, plugins []string) *DiscoveryServer {
	out := &DiscoveryServer{
		Env:                     env,
        ...
	}
    ...
	return out
}
```

可以看出server和DiscoveryServer都包含了同一个Environment对象，这个Environment对象内部有一个PushContext对象，它在创建Environment对象的内部进行创建，这个PushContext对象在server和envoy交互时起着举足轻重的作用，通过它可以获取所有配置信息，包括kube svc、istio crd等，向envoy推送的各种配置就是通过PushContext来获取并生成的。

pilot discovery server与envoy的交互分成两种方式：第一种是建立连接后envoy主动向discovery server发起请求，后者进行回应，第二种是当pilot discovery server发现配置信息(包括kube svc、istio crd等)修改了之后主动向envoy推送消息，下面分别来分析这两种不同的处理逻辑。

## 三、相关数据结构的初始化 ##

入口函数在`StreamAggregatedResources()`，关于如何注册以及如何跳转到这个地方可以参考`https://github.com/envoyproxy/go-control-plane`，里面的README以及一些example。

当envoy向server发起请求后，server使用这个函数来对envoy连接进行处理，下面是整体的框架

```
func (s *DiscoveryServer) StreamAggregatedResources(stream ads.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {

	err := s.globalPushContext().InitContext(s.Env, nil, nil)

	con := newXdsConnection(peerAddr, stream)

	reqChannel := make(chan *xdsapi.DiscoveryRequest, 1)
	go receiveThread(con, reqChannel, &receiveError)

	for {
		select {
		case discReq, ok := <-reqChannel:

			switch discReq.TypeUrl {
			case ClusterType, v3.ClusterType:
				if err := s.handleCds(con, discReq); err != nil {
					return err
				}
			case ListenerType, v3.ListenerType:
				if err := s.handleLds(con, discReq); err != nil {
					return err
				}
			case RouteType, v3.RouteType:
				if err := s.handleRds(con, discReq); err != nil {
					return err
				}
			case EndpointType, v3.EndpointType:
				if err := s.handleEds(con, discReq); err != nil {
					return err
				}
			default:
				adsLog.Warnf("ADS: Unknown watched resources %s", discReq.String())
			}
		case pushEv := <-con.pushChannel:
			// It is called when config changes.
            ...
			err := s.pushConnection(con, pushEv)
			pushEv.done()
			if err != nil {
				return nil
			}
		}
	}
}
```

主要分为以下几个步骤

1. 如果全局的PushContext对象没有初始化，则将其初始化。代码中先用`s.globalPushContext()`来获取`Environment.PushContext`，再用`InitContext()`来将其初始化。
2. 当envoy proxy向DiscoveryServer发起连接的时候，会在内部创建针对这个envoy proxy的XdsConnection对象。`con := newXdsConnection(peerAddr, stream)` 这时连接已经正常建立，初始化阶段结束，会进入监听状态，DiscoveryServer会监听envoy proxy发起的请求。
3. envoy proxy发起第一个具体的请求，DiscoveryServer会从XdsConnection对象中读取数据流，从数据流中提取出DiscoveryRequest对象。

   ```
        reqChannel := make(chan *xdsapi.DiscoveryRequest, 1)
        go receiveThread(con, reqChannel, &receiveError)

        for {
            // Block until either a request is received or a push is triggered.
            select {
            case discReq, ok := <-reqChannel:
                if !ok {
                    // Remote side closed connection.
                    return receiveError
                }
        ...
   ```

   ```
    func receiveThread(con *XdsConnection, reqChannel chan *xdsapi.DiscoveryRequest, errP *error) {
        for {
            req, err := con.stream.Recv()
            ...
            }
            select {
            case reqChannel <- req:
            case <-con.stream.Context().Done():
                ...
                return
            }
        }
    }
   ```

4. 根据DiscoveryRequest的Node成员变量，创建针对当前envoy proxy的Proxy对象并将其初始化(包括Proxy中SidecarScope等成员的初始化)，然后将它存到XdsConnection中的node成员变量中。注意，这一步只在envoy proxy第一次发起具体请求时执行，因为只需要执行一次。

    ```
			// This should be only set for the first request. The node id may not be set - for example malicious clients.
			if con.node == nil {
				if err := s.initConnection(discReq.Node, con); err != nil {
					return err
				}
				defer s.removeCon(con.ConID)
			}
    ```

5. 根据envoy proxy发出的不同类型的请求进行分别处理

## 四、server接受envoy的请求后推送配置 ##

接下来根据envoy的请求类型分别进行处理。下面以envoy请求Cluster类型的资源为例详细分析。

```
func (s *DiscoveryServer) handleCds(con *XdsConnection, discReq *xdsapi.DiscoveryRequest) error {
    ...
	err := s.pushCds(con, s.globalPushContext(), versionInfo())
	if err != nil {
		return err
	}
	return nil
}
```

会将`Environment.PushContext`作为第二个参数传递给`pushCds()`

```
func (s *DiscoveryServer) pushCds(con *XdsConnection, push *model.PushContext, version string) error {
    ...
	rawClusters := s.ConfigGenerator.BuildClusters(con.node, push)

    ...
	response := cdsDiscoveryResponse(rawClusters, push.Version, con.RequestedTypes.CDS)
	err := con.send(response)
    ...
}
```

进而将`Environment.PushContext`作为第二个参数传递给`BuildClusters()`，通过这个函数来获取所有的cluster数据。

```
func (configgen *ConfigGeneratorImpl) BuildClusters(proxy *model.Proxy, push *model.PushContext) []*apiv2.Cluster {
	clusters := make([]*apiv2.Cluster, 0)
	cb := NewClusterBuilder(proxy, push)
	instances := proxy.ServiceInstances

	outboundClusters := configgen.buildOutboundClusters(proxy, push)

    ...

	switch proxy.Type {
	case model.SidecarProxy:
        ...
		clusters = append(clusters, outboundClusters...)
		clusters = append(clusters, inboundClusters...)

	default: // Gateways
        ...
		outboundClusters = envoyfilter.ApplyClusterPatches(networking.EnvoyFilter_GATEWAY, proxy, push, outboundClusters)
		clusters = outboundClusters
	}

	clusters = normalizeClusters(push, proxy, clusters)

	return clusters
}
```

`BuildClusters()`里的逻辑涉及到具体的envoy配置，分为多种不同的cluster，详细的分析过程可以关注这个系列的后续文章。这里重点关注PushContext的使用，这里以其中的`buildOutboundClusters()`为例

```
func (configgen *ConfigGeneratorImpl) buildOutboundClusters(proxy *model.Proxy, push *model.PushContext) []*apiv2.Cluster {
	clusters := make([]*apiv2.Cluster, 0)
    ...

	var services []*model.Service
	if features.FilterGatewayClusterConfig && proxy.Type == model.Router {
		services = push.GatewayServices(proxy)
	} else {
		services = push.Services(proxy)
	}
	for _, service := range services {
        ...
	}

	return clusters
}
```

可以看到这里根据envoy proxy的类型，分情况获取所有service的列表，然后进行数据转换并存储到`clusters`中。获取service列表最终调用的函数则是PushContext的GatewayServices()或者Services()。

至此，可以看出PushContext参数在整个流程中是如何被传递以及使用的，它的核心作用就是作为一个获取Istio虚拟对象(包括kube svc和istio crd等)列表的一个媒介。

另外关于`StreamAggregatedResources()`中`case pushEv := <-con.pushChannel:`的分析请见下一节。

## 五、server主动推送配置给envoy ##

`DiscoveryServer`有一个`pushQueue`字段，是一个用来存储push操作的队列，当需要给envoy推送配置的时候，会将这个请求加入队列，在后续处理的时候，再出队列进行真正的push操作。

```
type PushQueue struct {
	mu   *sync.RWMutex
	cond *sync.Cond

	// eventsMap stores all connections in the queue. If the same connection is enqueued again, the
	// PushEvents will be merged.
	eventsMap map[*XdsConnection]*model.PushRequest

	// connections maintains ordering of the queue
	connections []*XdsConnection

    ...
}
```

它里面主要存储连接对象XdsConnection(即discovery server与envoy proxy的连接)和需要发送到这个envoy proxy连接的请求。

根据push request加入到pushQueue里这个时间点，可以将整个流程分成上半场和下半场。

### 上半场 ###

下面是上半场的函数调用时序图，注意这个图主要关注函数的调用过程，而不是严格的执行时序。

![discoveryserver_sequence_1](../discoveryserver_sequence_1.png)

`DiscoveryServer`有一个`pushChannel`字段，是一个用来暂存push操作的chan

```
type PushQueue struct {
	pushChannel chan *model.PushRequest
    ...
}
```

在初始化的时候，将它的大小设置为10

```
func NewDiscoveryServer(env *model.Environment, plugins []string) *DiscoveryServer {
	out := &DiscoveryServer{
        ...
		pushChannel:             make(chan *model.PushRequest, 10),
        ...
	}
    ...
	return out
}
```

当discovery server在watch到Config对象(包括kube svc对象和istio crd等)有更新的时候，会将push请求发送给这个chan

```
func (s *DiscoveryServer) ConfigUpdate(req *model.PushRequest) {
	inboundConfigUpdates.Increment()
	s.pushChannel <- req
}
```

当配置改变时，几乎都是通过调用这里的`ConfigUpdate()`来传递向envoy proxy主动推送的请求，这个函数在代码中被大量引用。

当DiscoveryServer启动后，有一个专门的函数来从DiscoveryServer.pushChannel中取得请求数据

```
func (s *DiscoveryServer) Start(stopCh <-chan struct{}) {
    ...
	go s.handleUpdates(stopCh)
    ...
}

func (s *DiscoveryServer) handleUpdates(stopCh <-chan struct{}) {
	debounce(s.pushChannel, stopCh, s.Push)
}
```

里面的`debounce()`并非从pushChannel中取得request数据就立即发送给envoy，而是有一个请求合并的处理。

经过一步步调用，最终会将envoy connection和request加入到`pushQueue`队列中

### 下半场 ###

![discoveryserver_sequence_2](../discoveryserver_sequence_2.png)

在DiscoveryServer启动后，有一个函数从DiscoveryServer.pushQueue这个队列中取出envoy connection和对应的push request对象

```
func (s *DiscoveryServer) Start(stopCh <-chan struct{}) {
    ...
	go s.sendPushes(stopCh)
}


func (s *DiscoveryServer) sendPushes(stopCh <-chan struct{}) {
	doSendPushes(stopCh, s.concurrentPushLimit, s.pushQueue)
}


func doSendPushes(stopCh <-chan struct{}, semaphore chan struct{}, queue *PushQueue) {
	for {
		select {
        ...
		default:
            ...
			client, info := queue.Dequeue()
            ...

			go func() {
				pushEv := &XdsEvent{
					full:           info.Full,
					push:           info.Push,
					done:           doneFunc,
					start:          info.Start,
					configsUpdated: info.ConfigsUpdated,
					noncePrefix:    info.Push.Version,
				}

				select {
				case client.pushChannel <- pushEv:
					return
                ...
				}
			}()
		}
	}
}
```

可以看到在调用doSendPushes()的时候将DiscoveryServer.pushQueue作为了第三个参数，而在doSendPushes()内部则会从pushQueue队列中取出envoy connection和对应的push request对象，并生成XdsEvent，最后将其存入envoy connection的pushChannel中。

接下来的处理逻辑在`StreamAggregatedResources()`这个函数中，这个函数的其它内容请见上一节的内容，这里只关注envoy connection的pushChannel的处理。

```
func (s *DiscoveryServer) StreamAggregatedResources(stream ads.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
    ...
	con := newXdsConnection(peerAddr, stream)

	reqChannel := make(chan *xdsapi.DiscoveryRequest, 1)
	go receiveThread(con, reqChannel, &receiveError)

	for {
		select {
		case discReq, ok := <-reqChannel:
            ...
		case pushEv := <-con.pushChannel:
			// It is called when config changes.
            ...
			err := s.pushConnection(con, pushEv)
			pushEv.done()
			if err != nil {
				return nil
			}
		}
	}
}
```

这里会从envoy connection的pushChannel中返回刚才存入的数据，再调用pushConnection()进行处理，在pushConnection()内部则会根据request的类型分别调用对应的push操作进行真正的推送。
