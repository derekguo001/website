---
title: "流量管理"
linkTitle: "流量管理"
weight: 1
date: 2017-01-05
description: >
---

Istio中对流量管理的两个基本的CRD对象是VirtualService和DestinationRule。下面通过一个例子来简要说明一下这两种对象的作用。

假设有一个服务webservice，包含了一些pod，这些pod分成两组，其中一部分pod带有app:v1的label，而另一部分pod带有app:v2的label。这两个label代表了这个服务的两个不同的版本。

我们的预期目标是将一部分流量(用户名为userA)导流到v2版本的负载，而其它流量导流到v1版本。

首先，需要使用DestinationRule来区分这些不同的pod集合，在Istio中被称为subset。

```
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name:
spec:
  host: webservice
  subsets:
  - name: v1subset
    labels:
      app: v1
  - name: v2subset
    labels:
      app: v2
```

接下来需要定义一个VirtualService对象来将流量路由到对应的负载上。

```
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: myvirtualservice
spec:
  hosts:
  - webservice
  http:
  - match:
    - headers:
        end-user:
          exact: userA
    route:
    - destination:
        host: webservice
        subset: v2subset
  - route:
    - destination:
        host: webservice
        subset: v1subset
```

至此，可以大概看出VirtualService和DestinationRule的基本作用：

DestinationRule定义了后端负载的subset。而VirtualService则是定义流量如何被路由到指定的subset。

除了这些基本功能之外VirtualService和DestinationRule还定义了一些其特性，比如上例中VirtualService使用的是基于http协议的路由配置，除此之外还可以使用tcp的或者tls协议的路由配置。DestinationRule还可以定义后端负载的策略，默认的是轮询，也可以配置成最小连接数、随机等等策略，还可以设置tls相关的配置，具体可以参考官方手册。
