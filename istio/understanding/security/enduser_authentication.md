---
title: "对终端用户的认证"
date: 2017-01-05
weight: 2
description: >
---

![enduser_authentication_1](../enduser_authentication_1.png)

对终端用户的认证是指对于发出请求的用户进行认证，当Pod A需要访问Pod B时，在Pod A内部发出到Pod B的请求，这个请求本身携带了某种Token(例如JWT)，然后请求会被Envoy Proxy A劫持，接着请求会由Envoy Proxy A发送给Envoy Proxy B，这时Envoy Proxy B会根据配置对请求中的Token进行验证，如果验证通过，则Envoy Proxy B会将请求转发给Pod B；如果Token认证失败，则请求被拒绝，不会发送给Pod B。


Istio中双向tls认证的基本对象是

```
apiVersion: "security.istio.io/v1beta1"
kind: "RequestAuthentication"
```

## 测试case1 对ingress进行配置 ##

TODO

## 测试case1 对sidecar进行配置 ##

TODO
