---
title: "第二章 CA Server"
linkTitle: "第二章 CA Server"
weight: 2
date: 2017-01-04
description: >
---

{{< figure src="../caserver_data_1.png" link="../caserver_data_1.png" target="_blank" >}}

## 一、对象模型 ##

在Istiod内部有一个名为CA Server服务的组件，用来提供证书签名的服务。Pilot Agent内部的SDS Server会向CA Server发起签名请求，CA Server会针对请求进行应答。

SDS Server和CA Server之间进行通信时的接口名为`IstioCertificateServiceServer`，它只包含了一个函数`CreateCertificate()`，一方面SDS Server会通过gRPC调用这个函数，另一方面在CA Server中有一个名为`pkg.server.ca.Server`的对象会实现`IstioCertificateServiceServer`这个Interface中的`CreateCertificate()`函数以便对请求进行应答。

除了实现`IstioCertificateServiceServer`这个Interface之外，`pkg.server.ca.Server`还实现了另外一个Interface，名为`IstioCAServiceServer`，其中的函数名为`HandleCSR()`，这个Interface和函数已经被标记为过时的，我们在后续的文章中将不会对其进行分析，不过为了保持代码完整性，仍然把它包含在对象模型的图中。

现在回头看`pkg.server.ca.Server`

```
type Server struct {
    ...
	Authenticators []authenticator
	ca             CertificateAuthority
    ...
}
```

其中有两个核心字段

- `Authenticators`

  第一个是`Authenticators`，它是`authenticator`类型的数组，在与SDS Server进行交互时，CA Server通过这个字段来对客户端的身份进行验证。

  `authenticator`是一个Interface类型，代码中包含了四种实现

  |认证类型|说明|
  |--|--|
  |ClientCertAuthenticator    |客户端证书认证|
  |IDTokenAuthenticator       |通过OpenID Connect (OIDC) 对客户端请求中的`Bearer`值进行认证，用于google公有云|
  |KubeJWTAuthenticator       |通过kubeclient向Kubernetes API Server发起验证请求，验证请求中的JWT Token|
  |jwtAuthenticator           |通过OpenID Connect (OIDC) 向Kubernetes API Server验证请求中的JWT Token，主要用于Istiod部署于Kubernetes集群之外的场景|

  `authenticator`定义如下

  ```
  type authenticator interface {
      Authenticate(ctx context.Context) (*authenticate.Caller, error)
      AuthenticatorType() string
  }
  ```

  其中的`AuthenticatorType()`返回字符串表示的类型，`Authenticate()`进行真正的验证工作。

- `ca`

  `ca`字段的类型为`CertificateAuthority`

  ```
  // CertificateAuthority contains methods to be supported by a CA.
  type CertificateAuthority interface {
      // Sign generates a certificate for a workload or CA, from the given CSR and TTL.
      // TODO(myidpt): simplify this interface and pass a struct with cert field values instead.
      Sign(csrPEM []byte, subjectIDs []string, ttl time.Duration, forCA bool) ([]byte, error)
      // SignWithCertChain is similar to Sign but returns the leaf cert and the entire cert chain.
      SignWithCertChain(csrPEM []byte, subjectIDs []string, ttl time.Duration, forCA bool) ([]byte, error)
      // GetCAKeyCertBundle returns the KeyCertBundle used by CA.
      GetCAKeyCertBundle() util.KeyCertBundle
  }
  ```

  CA Server在处理SDS Server的请求时，就是通过其中的`Sign()`对客户端的证书签名请求进行签名生成证书，然后再返回给客户端。

  这个Interface中的另一个函数`SignWithCertChain()`用于CA Server的服务器端证书签名，即CA Server对外提供 服务时，客户端需要对CA Server进行身份验证，因此CA Server也需要配置好服务器端证书，这个证书就是使用`SignWithCertChain()`进行签署的。

  这个Interface中的最后一个函数`GetCAKeyCertBundle()`用来返回根证书、私钥、证书、证书链等等证书实体对象，为了方便CA Server在内部将这些证书对象整合成为一个对象`KeyCertBundle`，然后通过`GetCAKeyCertBundle()`将它们一起返回。这个函数和`Sign()`以及`SignWithCertChain()`一起使用

一个名为`IstioCA`结构实现了`CertificateAuthority`接口，因此在`pkg.server.ca.Server`结构中的`ca`字段实际上就是一个`IstioCA`结构。

```
// IstioCA generates keys and certificates for Istio identities.
type IstioCA struct {
    ...
	keyCertBundle util.KeyCertBundle
	rootCertRotator *SelfSignedCARootCertRotator
}
```


其中有两个重要成员

- keyCertBundle，为`util.KeyCertBundle`类型，把相关证书都绑定到一起，这个整体的对象提供了一些接口
- rootCertRotator，为`*SelfSignedCARootCertRotator`类型，如果是自签名证书的话这个值为空，否则是一个轮询对象，会周期性地更新相关证书

另外，在签名关于Pilot Agent代码分析的文章中提到了Pilot Agent中核心对象是`pilot.pkg.bootstrap.Server`，它内部也有一个`ca`对象

```
type Server struct {
    ...
	ca               *ca.IstioCA
}
```

这个ca对象就是`IstioCA`结构，通过这种方式将CA Server与Pilot Agent主进程联系起来。

## 二、运行过程 ##

TODO
