---
title: "第一章 概述"
linkTitle: "第一章 概述"
weight: 1
date: 2017-01-04
description: >
---

## 概述 ##

本章描述在Istio中进行证书管理的主要组件和流程。

在阅读本文的同时先参考以下一些非常优秀的文章，都来自于赵化冰的博客
- [数字证书原理](https://zhaohuabing.com/post/2020-03-19-pki/)
- [一文带你彻底厘清 Kubernetes 中的证书工作机制](https://zhaohuabing.com/post/2020-05-19-k8s-certificate/)
- [一文带你彻底厘清 Isito 中的证书工作机制](https://zhaohuabing.com/post/2020-05-25-istio-certificate/)

组件说明

{{< figure src="../ca_1.png" link="../ca_1.png" width="80%" target="_blank" >}}

- 在Istiod内部有一个名为CA Server服务的组件，用来提供证书签名的服务。
- 上图中Pod A是用户的负载，伴随着Pod A是Istio注入的sidecar，启动的主进程被称为Pilot Agent，它核心的功能是启动Envoy进程来劫持并管理Pod A的进出口流量，除此之外，在Pilot Agent还有一个名为SDS Server的组件，用来生成私钥和证书签名请求文件并向CA Server发起证书签名请求。
- CA Server和SDS Server通信时，需要验证对方的身份，这时双方都需要有一个公共的CA根证书，这个根证书最初由CA Server在启动时创建，并存储于Kubernetes一个名为istio-ca-root-cert的ConfigMap对象中。这个ConfigMap会在注入sidecar时，挂载到sidecar的`/var/run/secrets/istio`目录中，随后当SDS Server与CA Server交互时会读取这个根证书，并用它创建client然后进行通信。

主要的流程如下

1. 当Envoy进程在与其它Envoy进程交互时，发现需要进行TLS认证，它会从静态配置文件或者动态配置服务器获取证书的名称等相关信息，这时Envoy进程就会通过SDS API向Pilot Agent中的SDS Server发起请求获取证书
2. SDS Server收到请求后，会首先读取本地的ServiceAccount Token，路径为`/var/run/secrets/kubernetes.io/serviceaccount/token`，然后从token中解析出namespace和ServiceAccount等信息，再用这些信息生成私钥和证书签名请求文件。接下来使用证书签名请求文件作为参数，向Istiod发起申请证书签名的请求
3. Istiod中的CA Server收到请求后会对其中的凭证进行验证，通过后会对根据请求对证书进行签名、生成证书，并将签名后的数字证书发送给SDS Server
4. SDS Server将私钥和从CA Server处获得的证书一起通过SDS API发送给Envoy
5. 以上过程会周期性地重复执行以便实现证书的轮换

## CA Server ##

Istiod内部的CA Server用来提供证书签名服务。

内部管理4个证书，都会挂载到`/etc/cacerts/`目录下

|路径|证书名称|
|--|--|
|/etc/cacerts/ca-key.pem   |ca私钥  |
|/etc/cacerts/ca-cert.pem  |ca证书  |
|/etc/cacerts/ca-chain.pem |ca证书链|
|/etc/cacerts/root-cert.pem|根证书  |

- ca证书用于给集群中的工作负载进行签名，即对Pilog Agent发起的CSR请求进行签名
- ca证书和ca私钥必须由根证书签名
- ca证书链是ca证书与根证书之间的信任链

这些证书有两种方式来创建

1. 自动生成，这种被称为自签名证书，这是默认的方式
2. 用户手动创建，即手动插入已存在的CA证书。可以在部署Istiod前使用已存在的证书在istio-system中创建名为cacerts的secret，然后istio部署的时候会自动使用这个secret中的证书，具体可以参考Istio官方手册 [Plugging in existing CA Certificates](https://istio.io/latest/docs/tasks/security/cert-management/plugin-ca-cert/)

有2个函数可以用来处理Pilot Agent发送过来的CSR请求。`CreateCertificate()`和`HandleCSR()`，其中第二个被标记为过时的。

## 相关的Kubernetes资源 ##

- istio-ca-secret secret

  位于istio-system中，用来持久化保存自签名的ca私钥和ca证书，其它字段都为空，只由Istiod使用，与Pilot Agent没有关系

  ``` bash
  [root@master1 ~]# kubectl get secret istio-ca-secret -n istio-system -o yaml
  apiVersion: v1
  data:
    ca-cert.pem: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
    ca-key.pem: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLR...
    cert-chain.pem: ""
    key.pem: ""
    root-cert.pem: ""
  kind: Secret
  metadata:
    creationTimestamp: "2020-05-25T07:31:18Z"
    name: istio-ca-secret
    namespace: istio-system
    resourceVersion: "2448"
    selfLink: /api/v1/namespaces/istio-system/secrets/istio-ca-secret
    uid: b58371c8-9822-4b37-94a1-dd92cf8de43d
  type: istio.io/ca-root
  ```

- istio-ca-root-cert configmap

  每个namespace中都会有一个，用于保存根证书，会挂载到Pilot Agent的`/var/run/secrets/istio`目录

  ``` bash
  [root@master1 ~]# kubectl get cm istio-ca-root-cert -n istio-system -o yaml
  apiVersion: v1
  data:
    root-cert.pem: |
      -----BEGIN CERTIFICATE-----
      MIIC3jCCAcagAwIBAgIRANmOZWfMlXfWKMj1xqISuCIwDQYJKoZIhvcNAQELBQAw
      ...
      -----END CERTIFICATE-----
  kind: ConfigMap
  metadata:
    creationTimestamp: "2020-05-25T07:31:19Z"
    labels:
      istio.io/config: "true"
    name: istio-ca-root-cert
    namespace: istio-system
    resourceVersion: "2473"
    selfLink: /api/v1/namespaces/istio-system/configmaps/istio-ca-root-cert
    uid: ce0fdfa7-0be5-4575-a0c6-1a2c053266f8
  [root@master1 ~]#
  ```

- istio-security configmap

  位于istio-system中，用来保存根证书。之前使用在nodeagent中，目前nodeagent已经集成到Pilot Agent中，根证书改为从istio-ca-root-cert configmap中获取，目前代码有注释说明保留这个只是为了向前兼容，代码中并没有实际使用，以后会从代码中完全移除

- cacerts secret

  会挂载到Istiod的`/etc/cacerts`目录，用户可以手动通过现有证书创建这个secret，然后再部署Istio，这样Istio就可以使用用户指定的证书

## SDS Server ##

### 控制面证书 ###

SDS Server与Istiod内部的CA Server进行通信时，双方都需要有一个根证书，用来验证对方的身份，根据配置的不同，这个根证书有几种不同的获取方式，对应的类型名称为分别为`istiod`、`kubernetes`和`custom`

|配置的类型名称|说明|备注|
|--|--|--|
|istiod|使用Istiod根证书|这是默认的方式，会从pod中以下位置读取`/var/run/secrets/istio/root-cert.pem`，这个文件夹是istio-ca-root-cert的ConfigMap挂载到pod上的内容，这个ConfigMap实际上是Istiod中的CA Server创建的。这就是本文中之前一直提到的默认的方式|
|kubernetes|使用Kubernetes根证书|会从pod中以下位置读取`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`|
|custom|使用自定义证书|会从`/etc/certs/root-cert.pem`中读取。|

下面来看一下注入的sidecar的模板文件

``` yaml
      "global": {
        ...
        "pilotCertProvider": "istiod",

        ...
      }

    template: |
        ...
        env:
        - name: JWT_POLICY
          value: {{ .Values.global.jwtPolicy }}
        - name: PILOT_CERT_PROVIDER
          value: {{ .Values.global.pilotCertProvider }}
        ...

        volumeMounts:
        {{- if eq .Values.global.pilotCertProvider "istiod" }}
        - mountPath: /var/run/secrets/istio
          name: istiod-ca-cert
        {{- end }}
        ...

      volumes:
      {{- if eq .Values.global.pilotCertProvider "istiod" }}
      - name: istiod-ca-cert
        configMap:
          name: istio-ca-root-cert
      {{- end }}
```

可以看出在部署的时候是通过`pilotCertProvider`这个参数来控制的，默认值是`istiod`，在模板文件中会将这个参数的值设置到环境变量`PILOT_CERT_PROVIDER`中。当这个值是`istiod`的情况下，会将`istio-ca-root-cert`这个configmap挂载到`/var/run/secrets/istio`目录中。

### 数据面证书 ###

数据面证书是指Envoy与Envoy通信时需要的证书，这些证书是Envoy通过向Pilot Agent中的SDS Server发起SDS请求获取的，而SDS Server内部获取这些证书的方式其实有两种：

1. SDS Server内部生成私钥和证书签名请求文件，然后再向Istiod内部的CA Server发起签名请求，最后将签名后的证书和私钥一起发送给Envoy。这就是前文中一直提到的情况，也是默认值。

2. SDS Server读取挂载的静态证书文件，将这些

   下面来看一下注入的sidecar的模板文件

   ``` yaml
         "global": {
           ...
           "mountMtlsCerts": false,
           ...
         }

       template: |
           ...

           volumeMounts:
           {{- if .Values.global.mountMtlsCerts }}
           # Use the key and cert mounted to /etc/certs/ for the in-cluster mTLS communications.
           - mountPath: /etc/certs/
             name: istio-certs
             readOnly: true
           {{- end }}
           ...

         volumes:
         {{- if .Values.global.mountMtlsCerts }}
         # Use the key and cert mounted to /etc/certs/ for the in-cluster mTLS communications.
         - name: istio-certs
           secret:
             optional: true
             {{ if eq .Spec.ServiceAccountName "" }}
             secretName: istio.default
             {{ else -}}
             secretName: {{  printf "istio.%s" .Spec.ServiceAccountName }}
             {{  end -}}
         {{- end }}
   ```

   如果是这种手动插入证书的方式，则SDS Server会将用户配置的证书直接返回给Envoy，而不是像前一种情况那样本地生成私钥和证书签名请求然后向CA Server申请签名。
