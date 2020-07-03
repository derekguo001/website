---
title: "第一章 Pilot Discovery概述"
linkTitle: "第一章 概述"
weight: 1
date: 2017-01-04
description: >
---

![pilot_discovery_1](../pilot_discovery_1.png)

这是pilot discovery简化版的架构图，左边的ConfigController和ServiceController会作为所有对象的信息源。其中ConfigController获取的对象主要包括VirtualService、DestinationRule等一些crd对象，而ServiceController获取的则是Kubernetes Service和Endpoint等对象。

在pilot discovery内部有一个DiscoveryServer，它一方面通过ConfigController和ServiceController获取各种对象，另一方面会与envoy进行通信。

和envoy通信有两种方式：
1. 当ConfigController和ServiceController发现有对象发生变化，例如用户新建了一个对象，它会通知DiscoveryServer，后者会更新内部的数据，然后将更新后的数据进行格式转化，最后将转化后的配置推送给envoy。
2. envoy主动向DiscoveryServer发起请求，DiscoveryServer则会根据请求类型，将内部的配置转化成envoy可以理解的格式返回。

接下来会按照不同的组件详细分析它们的模型定义、初始化以及和其它组件的交互过程。

代码版本为release-1.6分支。

有时为了着重描述核心内容，会简化一些细节。如果文章中有错误，请及时联系，我会在第一时间进行修改，另外也欢迎大家一起交流。微信是mcsos2048。

在文章撰写过程中，参考了其他人的一些文章，在这里向这些文章的作者致谢~

- [Istio Pilot代码深度解析](https://zhaohuabing.com/post/2019-10-21-pilot-discovery-code-analysis/) 来自赵化冰的博客
- [ Istio中的服务和流量的抽象模型](https://jimmysong.io/blog/istio-service-and-traffic-model/) 来自宋净超的博客
