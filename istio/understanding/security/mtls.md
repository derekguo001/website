---
title: "双向tls认证"
date: 2017-01-05
weight: 1
description: >
---

![mtls_1](../mtls_1.png)

双向tls的认证，是指两个Envoy Proxy之间的认证。Pod A需要访问Pod B，在Istio中，请求都是由Envoy进行代理的，因此完整的流程是Pod A发出到Pod B的请求，然后请求会被Envoy Proxy A劫持，接着Envoy Proxy A会与Envoy Proxy B进行点对点的认证，认证通过后，请求会由Envoy Proxy A发送给Envoy Proxy B，最后再由Envoy Proxy B将请求转发给Pod B。

在Envoy Proxy A与Envoy Proxy B之间认证的过程对于Pod A或者Pod B而言都是无感知的。

Istio中双向tls认证的基本对象是

```
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
```


## 认证配置的策略类型 ##

在具体进行配置的时候，有四种基本的策略

- DISABLE

  即禁用双向tls认证，这种情况下源Envoy与目的Envoy之间没有对对方进行身份的安全确认，它们之间发送的都是明文数据

- STRICT

  即严格的双向tls认证模式。源Envoy与目的Envoy之间必须对对方进行身份的安全确认，它们之间发送的都是加密后的数据。

- PERMISSIVE

  可以进行双向tls认证、也可以不进行认证从而发送明文数据。

- UNSET

  即没有进行设置，这种情况下会继承上级策略，比如当前namespace的或者整个系统的。如果上级策略都为空，则会默认设置为PERMISSIVE

## 认证配置的范围 ##

Istio中对双向tls认证进行配置的时候，可以有几种不同的范围，范围越小优先级越高：

- 全局

  ```
  apiVersion: security.istio.io/v1beta1
  kind: PeerAuthentication
  metadata:
    name: default
    namespace: istio-system
  spec:
    mtls:
      mode: STRICT
  ```

  注意，全局的安全策略名称只能是default，namespace则是istio所在的系统namespace，这里是istio-system

- namespace级别，即某个namespace中所有服务

  ```
  apiVersion: security.istio.io/v1beta1
  kind: PeerAuthentication
  metadata:
    name: default
    namespace: foo
  spec:
    mtls:
      mode: PERMISSIVE
  ```

- 负载级别，即某个namespace中某些具体的Pod

  ```
  apiVersion: security.istio.io/v1beta1
  kind: PeerAuthentication
  metadata:
    name: default
    namespace: foo
  spec:
    selector:
      matchLabels:
        app: finance
    mtls:
      mode: STRICT
  ```

  会将带有"app: finance"label的Pod所在的Envoy实行STRICT模式。

- 端口级别

  ```
  apiVersion: security.istio.io/v1beta1
  kind: PeerAuthentication
  metadata:
    name: default
    namespace: foo
  spec:
    selector:
      matchLabels:
        app: finance
    mtls:
      mode: STRICT
    portLevelMtls:
      8080:
        mode: DISABLE
  ```

  会将带有"app: finance"label的Pod所在的Envoy实行STRICT模式，但是会将其中的8080端口使用DISABLE模式。

## 认证配置的具体方法 ##

在Istio中进行双向tls认证配置，需要注意的是客户端和服务器端配置方法是不一样的。例如在namespace foo中有两组服务A和B，每组都有一些Pod，假设服务A的Pod对应的label为"app: A"，而服务B的Pod对应的label为"app: B"。这时在服务A所在的Pod中访问服务B，要将这一请求设置为STRICT模式，需要配置两处

1. 服务器端配置，给服务B对应的负载配置PeerAuthentication策略，这里配置的是服务B所有关联Pod对应的Envoy Proxy。

   ```
   apiVersion: security.istio.io/v1beta1
   kind: PeerAuthentication
   metadata:
     name: default
     namespace: foo
   spec:
     selector:
       matchLabels:
         app: B
     mtls:
       mode: STRICT
   ```

2. 客户端配置，给服务B配置DestinationRule策略。这里配置的是所有访问服务B的Pod对应的Envoy Proxy。

   ```
   cat <<EOF | kubectl apply -n foo -f -
   apiVersion: "networking.istio.io/v1alpha3"
   kind: "DestinationRule"
   metadata:
     name: "B"
   spec:
     host: "B.foo.svc.cluster.local"
     trafficPolicy:
       tls:
         mode: ISTIO_MUTUAL
   EOF
   ```

也就是说客户端配置的时候需要配置目的服务的DestinationRule对象，而服务器端配置的时候需要配置服务器端对应负载的PeerAuthentication对象。

## 测试case1 默认配置 ##

```
kubectl create ns foo
kubectl apply -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n foo
kubectl apply -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n foo
kubectl create ns bar
kubectl apply -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n bar
kubectl apply -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n bar
kubectl create ns legacy
kubectl apply -f samples/httpbin/httpbin.yaml -n legacy
kubectl apply -f samples/sleep/sleep.yaml -n legacy
```

创建了3个namespace：foo, bar和legacy，每个namespace分别创建了sleep和httpbin两种应用，作为客户端和服务器端。在foo和bar中的Pod有对应的Envoy Proxy，而在legacy中则没有。下面是创建成功后的Pod情况

```
[root@master1 istio-1.6.0]# kubectl get pod --all-namespaces
NAMESPACE      NAME                                    READY   STATUS    RESTARTS   AGE
bar            httpbin-67576779c-tjl4m                 2/2     Running   0          31m
bar            sleep-7dc44b8d45-rfhpl                  2/2     Running   0          31m
foo            httpbin-67576779c-tw6kl                 2/2     Running   0          31m
foo            sleep-7dc44b8d45-87x2p                  2/2     Running   0          31m
legacy         httpbin-779c54bf49-h5wrw                1/1     Running   0          31m
legacy         sleep-f8cbf5b76-b8xgd                   1/1     Running   0          31m
```

在使用默认的default配置部署Istio的情况下，如果没有设置任何安全策略，默认是PERMISSIVE，即同时允许双向tls认证和不进行任何认证的纯文本数据交换两种方式。注意这只针对有Envoy Proxy的情况，因为这些策略最终的执行者是Envoy，而对于那些没有Envoy Proxy的Pod，例如legacy中的Pod，则只能使用纯文本方式进行收发数据。下面来验证这一点

```
[root@master1 istio-1.6.0]# for from in "foo" "bar" "legacy"; do for to in "foo" "bar" "legacy"; do kubectl exec $(kubectl get pod -l app=sleep -n ${from} -o jsonpath={.items..metadata.name}) -c sleep -n ${from} -- curl "http://httpbin.${to}:8000/ip" -s -o /dev/null -w "sleep.${from} to httpbin.${to}: %{http_code}\n"; done; done
sleep.foo to httpbin.foo: 200
sleep.foo to httpbin.bar: 200
sleep.foo to httpbin.legacy: 200
sleep.bar to httpbin.foo: 200
sleep.bar to httpbin.bar: 200
sleep.bar to httpbin.legacy: 200
sleep.legacy to httpbin.foo: 200
sleep.legacy to httpbin.bar: 200
sleep.legacy to httpbin.legacy: 200
```

可以看到任何两个sleep与httpbin之间都是可以连通的。但是如果进一步观察，发现这些认证方式其实是不同的

```
[root@master1 istio-1.6.0]# kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl http://httpbin.foo:8000/headers -s | grep X-Forwarded-Client-Cert
    "X-Forwarded-Client-Cert": "By=spiffe://cluster.local/ns/foo/sa/httpbin;Hash=41eb8aa0a91782fc1a09df8da85b586c5eaabbca3117f645cdb9df8d998b55f2;Subject=\"\";URI=spiffe://cluster.local/ns/foo/sa/sleep"
```

从foo中的sleep访问foo中的httpbin，header中带有"X-Forwarded-Client-Cert"表明使用了双向tls认证。

```
[root@master1 istio-1.6.0]# kubectl exec $(kubectl get pod -l app=sleep -n legacy -o jsonpath={.items..metadata.name}) -c sleep -n legacy -- curl http://httpbin.foo:8000/headers -s | grep X-Forwarded-Client-Cert
[root@master1 istio-1.6.0]#
```

而从legacy中的sleep访问legacy中的httpbin，header中则不会带有"X-Forwarded-Client-Cert"，因为客户端和服务器端都没有Envoy Proxy，只能进行没有任何认证的纯文本数据交换的方式。

另外，还可以看出sleep.legacy发出去的请求都是纯文本类型，而sleep.httpbin收到的请求也都是纯文本类型。而foo和bar里面的Pod发送请求时则会优先使用双向tls认证方式(即下面四种)，这些可以自行测试验证。

```
sleep.foo to httpbin.foo: 200
sleep.foo to httpbin.bar: 200
sleep.bar to httpbin.foo: 200
sleep.bar to httpbin.bar: 200
```

清理命令

```
kubectl delete -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n foo
kubectl delete -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n foo
kubectl delete -f samples/httpbin/httpbin.yaml -n legacy
kubectl delete -f samples/sleep/sleep.yaml -n legacy
kubectl delete -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n bar
kubectl delete -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n bar
kubectl delete ns foo
kubectl delete ns legacy
kubectl delete ns bar
```

## 测试case2 针对特定服务的配置 ##

首先，创建一个全局的安全策略，禁用所有的双向tls认证。

```
kubectl apply -f - <<EOF
apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "default"
  namespace: "istio-system"
spec:
  mtls:
    mode: DISABLE
EOF
```

然后创建一个foo namespace，并在其中创建带有Envoy Proxy的sleep和httpbin

```
kubectl create ns foo
kubectl apply -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n foo
kubectl apply -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n foo
```

这时进行测试，会发现他们之间可以正常访问，但没有使用双向tls认证，这符合预期，说明全局策略生效。

```

[root@master1 istio-1.6.0]# kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl "http://httpbin.foo:8000/ip" -s -o /dev/null -w "sleep.foo to httpbin.foo: %{http_code}\n"
sleep.foo to httpbin.foo: 200
[root@master1 istio-1.6.0]# kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl http://httpbin.foo:8000/headers -s | grep X-Forwarded-Client-Cert
[root@master1 istio-1.6.0]#
```

接下来为服务器端配置PeerAuthentication策略，让其强制执行双向tls认证

```
cat <<EOF | kubectl apply -n foo -f -
apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "httpbin"
  namespace: "foo"
spec:
  selector:
    matchLabels:
      app: httpbin
  mtls:
    mode: STRICT
EOF
```

这时再次进行测试

```
[root@master1 istio-1.6.0]# kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl "http://httpbin.foo:8000/ip" -s -o /dev/null -w "sleep.foo to httpbin.foo: %{http_code}\n"
sleep.foo to httpbin.foo: 503
[root@master1 istio-1.6.0]#
```

出现了503错误，这其实是一个tls冲突，因为截至目前为止我们为服务器端设置了强制使用双向tls认证，但是客户端还未设置。

接下来设置客户端。

```
cat <<EOF | kubectl apply -n foo -f -
apiVersion: "networking.istio.io/v1alpha3"
kind: "DestinationRule"
metadata:
  name: "httpbin"
spec:
  host: "httpbin.foo.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
EOF
```

然后进行测试，发现现在已经可以正常访问，且使用了双向tls认证，符合预期。

```
[root@master1 istio-1.6.0]# kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl "http://httpbin.foo:8000/ip" -s -o /dev/null -w "sleep.foo to httpbin.foo: %{http_code}\n"
sleep.foo to httpbin.foo: 200
[root@master1 istio-1.6.0]# kubectl exec $(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name}) -c sleep -n foo -- curl http://httpbin.foo:8000/headers -s | grep X-Forwarded-Client-Cert
    "X-Forwarded-Client-Cert": "By=spiffe://cluster.local/ns/foo/sa/httpbin;Hash=b8a73b2655b270e23eda820e49c56cc9b16521d98cb6c1896eff41c58cc32d56;Subject=\"\";URI=spiffe://cluster.local/ns/foo/sa/sleep"
[root@master1 istio-1.6.0]#
```

清理命令

```
kubectl delete PeerAuthentication httpbin -n foo
kubectl delete DestinationRule httpbin -n foo
kubectl delete -f <(istioctl kube-inject -f samples/httpbin/httpbin.yaml) -n foo
kubectl delete -f <(istioctl kube-inject -f samples/sleep/sleep.yaml) -n foo
kubectl delete ns foo
```

## 参考 ##

- https://istio.io/docs/concepts/security/
- https://istio.io/docs/tasks/security/authentication/
- https://istio.io/docs/reference/config/security/peer_authentication/
- https://istio.io/docs/reference/config/networking/destination-rule
- https://zhaohuabing.com/post/2020-05-25-istio-certificate/
