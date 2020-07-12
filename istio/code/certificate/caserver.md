---
title: "第三章 CA Server"
linkTitle: "第三章 CA Server"
weight: 3
date: 2017-01-04
description: >
---

{{< figure src="../caserver_data_1.png" link="../caserver_data_1.png" target="_blank" >}}

## 一、对象模型 ##

在Istiod内部有一个名为CA Server服务的组件，用来提供证书签名的服务。Pilot Agent内部的SDS Server会向CA Server发起签名请求，CA Server会针对请求进行应答。

SDS Server和CA Server之间进行通信时的接口名为`IstioCertificateServiceServer`，它只包含了一个函数`CreateCertificate()`，一方面SDS Server会通过gRPC调用这个函数，另一方面在CA Server中有一个名为`pkg.server.ca.Server`的对象会实现`IstioCertificateServiceServer`这个Interface中的`CreateCertificate()`函数以便对请求进行应答。

除了实现`IstioCertificateServiceServer`这个Interface之外，`pkg.server.ca.Server`还实现了另外一个Interface，名为`IstioCAServiceServer`，其中的函数名为`HandleCSR()`，这个Interface和函数已经被标记为过时的，我们在后续的文章中将不会对其进行分析，不过为了保持代码完整性，仍然把它包含在对象模型的图中。

现在回头看`pkg.server.ca.Server`

``` golang
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
|IDTokenAuthenticator       |通过OpenID Connect (OIDC) 对客户端请求中的`Bearer`中的JWT Token进行认证，用于google公有云|
|KubeJWTAuthenticator       |通过kubeclient向Kubernetes API Server发起验证请求，验证请求中的JWT Token|
|jwtAuthenticator           |通过OpenID Connect (OIDC) 向Kubernetes API Server验证请求中的JWT Token，主要用于Istiod部署于Kubernetes集群之外的场景|

  `authenticator`定义如下

  ``` golang
  type authenticator interface {
      Authenticate(ctx context.Context) (*authenticate.Caller, error)
      AuthenticatorType() string
  }
  ```

  其中的`AuthenticatorType()`返回字符串表示的类型，`Authenticate()`进行真正的验证工作。

- `ca`

  `ca`字段的类型为`CertificateAuthority`

  ``` golang
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

``` golang
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

``` golang
type Server struct {
    ...
	ca               *ca.IstioCA
}
```

这个ca对象就是`IstioCA`结构，通过这种方式将CA Server与Pilot Agent主进程联系起来。

在整个Istiod的启动代码中，关于CA相关的主要执行框架如下

``` go
func NewServer(args *PilotArgs) (*Server, error) {
    ...
	if args.TLSOptions.CaCertFile == "" && s.EnableCA() {
		s.ca, err = s.createCA(corev1, caOpts)
        ...
	}

	if s.ca != nil {
		s.addStartFunc(func(stop <-chan struct{}) error {
			s.RunCA(s.secureGrpcServer, s.ca, caOpts)
			return nil
		})

    ...
}
```

1. 使用`createCA()`创建`CertificateAuthority`对象，也就是`IstioCA`结构。
2. 使用`RunCA()`来创建CA Server并将其启动

下面分别进行分析

## 二、IstioCA对象的创建和运行 ##

创建的代码位于`createCA()`中

``` golang
func (s *Server) createCA(client corev1.CoreV1Interface, opts *CAOptions) (*ca.IstioCA, error) {
    ...
	signingKeyFile := path.Join(LocalCertDir.Get(), "ca-key.pem")

	if _, err := os.Stat(signingKeyFile); err != nil {
        ...
		caOpts, err = ca.NewSelfSignedIstioCAOptions(ctx,
			selfSignedRootCertGracePeriodPercentile.Get(), SelfSignedCACertTTL.Get(),
			selfSignedRootCertCheckInterval.Get(), workloadCertTTL.Get(),
			maxCertTTL, opts.TrustDomain, true,
			opts.Namespace, -1, client, rootCertFile,
			enableJitterForRootCertRotator.Get())
        ...
	} else {
		log.Info("Use local CA certificate")

		caOpts, err = ca.NewPluggedCertIstioCAOptions(certChainFile, signingCertFile, signingKeyFile,
			rootCertFile, workloadCertTTL.Get(), maxCertTTL, opts.Namespace, client)
        ...
	}

	istioCA, err := ca.NewIstioCA(caOpts)
    ...
	istioCA.Run(rootCertRotatorChan)

	return istioCA, nil
}
```

整体逻辑如下，根据`./etc/cacerts/ca-key.pem`是否存在，决定是否采用自签名证书还是已存在的证书，可参见[CA Server]({{< relref "docs/istio/code/certificate/intro.md#ca-server" >}})

这两种情况最终都会生成一个`IstioCAOptions`对象，然后用它创建IstioCA，最后运行`IstioCA.Run()`

后两步其实都非常简单，代码如下

``` golang
// NewIstioCA returns a new IstioCA instance.
func NewIstioCA(opts *IstioCAOptions) (*IstioCA, error) {
	ca := &IstioCA{
		defaultCertTTL: opts.DefaultCertTTL,
		maxCertTTL:     opts.MaxCertTTL,
		keyCertBundle:  opts.KeyCertBundle,
		livenessProbe:  probe.NewProbe(),
	}

	if opts.CAType == selfSignedCA && opts.RotatorConfig.CheckInterval > time.Duration(0) {
		ca.rootCertRotator = NewSelfSignedCARootCertRotator(opts.RotatorConfig, ca)
	}
	return ca, nil
}
```

``` golang
func (ca *IstioCA) Run(stopChan chan struct{}) {
	if ca.rootCertRotator != nil {
		// Start root cert rotator in a separate goroutine.
		go ca.rootCertRotator.Run(stopChan)
	}
}
```

可以看出如果是自签名证书，则会创建`IstioCA.rootCertRotator`对象，然后在`IstioCA.Run()`中将其启动，关于自签名证书的轮换我们后续单独进行分析，这里不再展开。

现在回头来看，ca服务的创建过程中比较复杂的逻辑在于如何创建`IstioCAOptions`对象，下面分别来进行分析。

### 自签名证书 ###

如果`./etc/cacerts/ca-key.pem`不存在，则创建自签名证书。会调用`NewSelfSignedIstioCAOptions()`来实现

``` golang
func NewSelfSignedIstioCAOptions(...) (caOpts *IstioCAOptions, err error) {

	caSecret, scrtErr := client.Secrets(namespace).Get(context.TODO(), CASecret, metav1.GetOptions{})
    ...
	caOpts = &IstioCAOptions{
		CAType:         selfSignedCA,
		DefaultCertTTL: defaultCertTTL,
		MaxCertTTL:     maxCertTTL,
		RotatorConfig: &SelfSignedCARootCertRotatorConfig{
			CheckInterval:      rootCertCheckInverval,
			caCertTTL:          caCertTTL,
			retryInterval:      cmd.ReadSigningCertRetryInterval,
			certInspector:      certutil.NewCertUtil(rootCertGracePeriodPercentile),
			caStorageNamespace: namespace,
			dualUse:            dualUse,
			org:                org,
			rootCertFile:       rootCertFile,
			enableJitter:       enableJitter,
			client:             client,
		},
	}
	if scrtErr != nil {
		pkiCaLog.Infof("Failed to get secret (error: %s), will create one", scrtErr)
        ...
	} else {
		pkiCaLog.Infof("Load signing key and cert from existing secret %s:%s", caSecret.Namespace, caSecret.Name)
        ...
	}

	if err = updateCertInConfigmap(namespace, client, caOpts.KeyCertBundle.GetRootCertPem()); err != nil {
		pkiCaLog.Errorf("Failed to write Citadel cert to configmap (%v). Node agents will not be able to connect.", err)
	} else {
		pkiCaLog.Infof("The Citadel's public key is successfully written into configmap istio-security in namespace %s.", namespace)
	}
	return caOpts, nil
}
```

这里的整体逻辑是根据istio-ca-secret这个secret是否存在，决定是新建证书还是使用这个secret中的证书，等所有证书就绪后，会将证书绑定到一起形成`IstioCAOptions.KeyCertBundle`对象。然后会用根证书更新configmap，最后返回一个IstioCAOptions对象。

#### istio-ca-secret不存在的情况 ####

首次运行时，这个secret是不存在的

``` golang
    if scrtErr != nil {
        pkiCaLog.Infof("Failed to get secret (error: %s), will create one", scrtErr)
        ...
        pemCert, pemKey, ckErr := util.GenCertKeyFromOptions(options)
        ...
        rootCerts, err := util.AppendRootCerts(pemCert, rootCertFile)
        ...
        if caOpts.KeyCertBundle, err = util.NewVerifiedKeyCertBundleFromPem(pemCert, pemKey, nil, rootCerts); err != nil {
            return nil, fmt.Errorf("failed to create CA KeyCertBundle (%v)", err)
        }

        // Write the key/cert back to secret so they will be persistent when CA restarts.
        secret := k8ssecret.BuildSecret("", CASecret, namespace, nil, nil, nil, pemCert, pemKey, istioCASecretType)
        if _, err = client.Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
            pkiCaLog.Errorf("Failed to write secret to CA (error: %s). Abort.", err)
            return nil, fmt.Errorf("failed to create CA due to secret write error")
        }
        pkiCaLog.Infof("Using self-generated public key: %v", string(rootCerts))
    } else {
```

1. 使用`GenCertKeyFromOptions()`来创建ca的私钥和证书
2. 将ca证书加入到根证书中，将`./etc/cacerts/root-cert.pem`(由用户配置，如果没有配置则为空)，也会把它加到根证书里
3. 使用ca私钥、ca证书和根证书来创建IstioCAOptions.KeyCertBundle对象。
4. 用ca私钥和ca证书创建`istio-ca-secret` secret

#### istio-ca-secret存在的情况 ####

``` golang
    } else {
        pkiCaLog.Infof("Load signing key and cert from existing secret %s:%s", caSecret.Namespace, caSecret.Name)
        rootCerts, err := util.AppendRootCerts(caSecret.Data[caCertID], rootCertFile)
        if err != nil {
            return nil, fmt.Errorf("failed to append root certificates (%v)", err)
        }
        if caOpts.KeyCertBundle, err = util.NewVerifiedKeyCertBundleFromPem(caSecret.Data[caCertID],
            caSecret.Data[caPrivateKeyID], nil, rootCerts); err != nil {
            return nil, fmt.Errorf("failed to create CA KeyCertBundle (%v)", err)
        }
        pkiCaLog.Infof("Using existing public key: %v", string(rootCerts))
    }
```

读取istio-ca-secret

1. 将istio-ca-secret中的ca证书和`./etc/cacerts/root-cert.pem`(由用户配置了，如果没有配置则为空)一起组成根证书
2. 将istio-ca-secret中的ca证书和ca私钥以及刚才的根证书来创建IstioCAOptions.KeyCertBundle对象。

处理完istio-ca-secret，最后会将根证书以key:map形式插入到istio-security这个configmap中，key是caTLSRootCert，对应的value通过刚才的创建的KeyCertBundleImpl对象的GetRootCertPem()获取，实际上就是根证书的内容。如果configmap不存在则创建它，否则更新。

最后会返回在这个函数中创建的IstioCAOptions对象。

### 使用用户指定的证书 ###

参见[CA Server]({{< relref "docs/istio/code/certificate/intro.md#ca-server" >}})

实现的代码位于NewPluggedCertIstioCAOptions()

``` golang
// NewPluggedCertIstioCAOptions returns a new IstioCAOptions instance using given certificate.
func NewPluggedCertIstioCAOptions(certChainFile, signingCertFile, signingKeyFile, rootCertFile string,
	defaultCertTTL, maxCertTTL time.Duration, namespace string, client corev1.CoreV1Interface) (caOpts *IstioCAOptions, err error) {
	caOpts = &IstioCAOptions{
		CAType:         pluggedCertCA,
		DefaultCertTTL: defaultCertTTL,
		MaxCertTTL:     maxCertTTL,
	}
	if caOpts.KeyCertBundle, err = util.NewVerifiedKeyCertBundleFromFile(
		signingCertFile, signingKeyFile, certChainFile, rootCertFile); err != nil {
		return nil, fmt.Errorf("failed to create CA KeyCertBundle (%v)", err)
	}
```

首先会使用ca私钥、ca证书、ca证书链和根证书通过NewVerifiedKeyCertBundleFromFile创建IstioCAOptions.KeyCertBundle对象。

``` golang
	// Validate that the passed in signing cert can be used as CA.
	// The check can't be done inside `KeyCertBundle`, since bundle could also be used to
	// validate workload certificates (i.e., where the leaf certificate is not a CA).
	b, err := ioutil.ReadFile(signingCertFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not authorized to sign other certificates")
	}
```

上面代码的含义是验证ca证书的合法性

``` golang
	crt := caOpts.KeyCertBundle.GetCertChainPem()
	if len(crt) == 0 {
		crt = caOpts.KeyCertBundle.GetRootCertPem()
	}
	if err = updateCertInConfigmap(namespace, client, crt); err != nil {
		pkiCaLog.Errorf("Failed to write Citadel cert to configmap (%v). Node agents will not be able to connect.", err)
	}
	return caOpts, nil
}
```

然后使用ca证书链的内容来更新istio-security这个configmap，最后返回IstioCAOptions对象。

## 三、CA Server的创建和运行 ##

CA Server的创建和运行的代码位于`pilot/pkg/bootstrap/server.go`中

``` go
	// Run the SDS signing server.
	// RunCA() must be called after createCA() and initDNSListener()
	// because it depends on the following conditions:
	// 1) CA certificate has been created.
	// 2) grpc server has been started.
	if s.ca != nil {
		s.addStartFunc(func(stop <-chan struct{}) error {
			s.RunCA(s.secureGrpcServer, s.ca, caOpts)
			return nil
		})
        ...
	}
```

详细分析如下

``` go
func (s *Server) RunCA(grpc *grpc.Server, ca caserver.CertificateAuthority, opts *CAOptions) {
    ...

	iss := trustedIssuer.Get()
	aud := audience.Get()

	ch := make(chan struct{})
	token, err := ioutil.ReadFile(s.jwtPath)
	if err == nil {
		tok, err := detectAuthEnv(string(token))
		if err != nil {
			log.Warna("Starting with invalid K8S JWT token", err, string(token))
		} else {
			if iss == "" {
				iss = tok.Iss
			}
			if len(tok.Aud) > 0 && len(aud) == 0 {
				aud = tok.Aud[0]
			}
		}
	}

    ...
	caServer, startErr := caserver.NewWithGRPC(grpc, ca, maxWorkloadCertTTL.Get(),
		false, []string{"istiod.istio-system"}, 0, spiffe.GetTrustDomain(),
		true, features.JwtPolicy.Get(), s.clusterID, s.kubeClient,
		s.multicluster.GetRemoteKubeClient)

    ...
	if iss != "" && // issuer set explicitly or extracted from our own JWT
		k8sInCluster.Get() == "" { // not running in cluster - in cluster use direct call to apiserver
		oidcAuth, err := newJwtAuthenticator(iss, opts.TrustDomain, aud)
		if err == nil {
			caServer.Authenticators = append(caServer.Authenticators, oidcAuth)
			log.Infoa("Using out-of-cluster JWT authentication")
		} else {
			log.Infoa("K8S token doesn't support OIDC, using only in-cluster auth")
		}
	}

	caServer.Authenticators = append(caServer.Authenticators, &authenticate.ClientCertAuthenticator{})

	if serverErr := caServer.Run(); serverErr != nil {
        ...
	}
}
```

主要代码框架：

- 使用`NewWithGRPC()`创建CA Server对象
- 从jwt文件中提取出issuer和audience对象，如果issuer非空且Istiod运行在非Kubernetes集群中，则创建jwtAuthenticator对象
- 运行CA Server的`Run()`

### 创建CA Server对象 ###

``` go
func NewWithGRPC(grpc *grpc.Server, ca CertificateAuthority, ttl time.Duration, forCA bool,
	hostlist []string, port int, trustDomain string, sdsEnabled bool, jwtPolicy, clusterID string,
	kubeClient kubernetes.Interface,
	remoteKubeClientGetter authenticate.RemoteKubeClientGetter) (*Server, error) {

    ...
	authenticators := []authenticator{&authenticate.ClientCertAuthenticator{}}

	// Only add k8s jwt authenticator if SDS is enabled.
	if sdsEnabled {
		authenticator := authenticate.NewKubeJWTAuthenticator(kubeClient, clusterID, remoteKubeClientGetter,
			trustDomain, jwtPolicy)
		authenticators = append(authenticators, authenticator)
		serverCaLog.Info("added K8s JWT authenticator")
	}

    ...
	server := &Server{
		Authenticators: authenticators,
		authorizer:     &registryAuthorizor{registry.GetIdentityRegistry()},
		serverCertTTL:  ttl,
		ca:             ca,
		hostnames:      hostlist,
		forCA:          forCA,
		port:           port,
		grpcServer:     grpc,
		monitoring:     newMonitoringMetrics(),
	}
	return server, nil
}
```

这是创建CA Server的代码，主要的逻辑在于设置CA Server对SDS Server的认证方式。可以对照着[CA Server]({{< relref "docs/istio/code/certificate/intro.md#ca-server" >}})进行分析

1. 首先，添加`ClientCertAuthenticator`这种客户端证书认证的方式
2. 用`NewKubeJWTAuthenticator()`增加第二种客户端身份验证的方式，这种会使用kubeclient向Kubernetes API Server发起验证请求，验证SDS Server请求中的JWT Token

### 设置jwtAuthenticator对象 ###

在创建了CA Server后，会根据从jwt文件中读取的内容来创建jwtAuthenticator对象，代码如下

``` go

	token, err := ioutil.ReadFile(s.jwtPath)
	if err == nil {
		tok, err := detectAuthEnv(string(token))
		if err != nil {
			log.Warna("Starting with invalid K8S JWT token", err, string(token))
		} else {
			if iss == "" {
				iss = tok.Iss
			}
			if len(tok.Aud) > 0 && len(aud) == 0 {
				aud = tok.Aud[0]
			}
		}
	}

    ...

	if iss != "" && // issuer set explicitly or extracted from our own JWT
		k8sInCluster.Get() == "" { // not running in cluster - in cluster use direct call to apiserver
        ...
		oidcAuth, err := newJwtAuthenticator(iss, opts.TrustDomain, aud)
		if err == nil {
			caServer.Authenticators = append(caServer.Authenticators, oidcAuth)
			log.Infoa("Using out-of-cluster JWT authentication")
		} else {
			log.Infoa("K8S token doesn't support OIDC, using only in-cluster auth")
		}
	}
```

代码逻辑是，从jwt文件中提取出issuer和audience对象，如果issuer非空且Istiod运行在非Kubernetes集群中，则创建jwtAuthenticator对象，这种认证方式会通过OpenID Connect (OIDC) 向Kubernetes API Server验证请求中的JWT Token，主要用于Istiod部署于Kubernetes集群之外的场景。

### 运行CA Server对象 ###

在创建完CA Server对象，且配置好其对SDS Server客户端认证的方式后，会执行`Run()`操作。代码位于`security/pkg/server/ca/server.go`中的`Run()`，代码主要设置gRPC相关的一些参数，在这里不再详细展开。其中有一个步骤是创建服务器端证书

``` go
		grpcOptions = append(grpcOptions, s.createTLSServerOption(), grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor))
```

代码如下

``` go
func (s *Server) createTLSServerOption() grpc.ServerOption {
	cp := x509.NewCertPool()
	rootCertBytes := s.ca.GetCAKeyCertBundle().GetRootCertPem()
	cp.AppendCertsFromPEM(rootCertBytes)

	config := &tls.Config{
		ClientCAs:  cp,
		ClientAuth: tls.VerifyClientCertIfGiven,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if s.certificate == nil || shouldRefresh(s.certificate) {
				newCert, err := s.getServerCertificate()
                ...
				s.certificate = newCert
			}
			return s.certificate, nil
		},
	}
	return grpc.Creds(credentials.NewTLS(config))
}
```

通过IstioCA对象来获取根证书，并且使用`getServerCertificate()`来获取服务器端证书

``` go
func (s *Server) getServerCertificate() (*tls.Certificate, error) {
	opts := util.CertOptions{
		RSAKeySize: 2048,
	}

    ...
	csrPEM, privPEM, err := util.GenCSR(opts)
	if err != nil {
		return nil, err
	}

	certPEM, signErr := s.ca.SignWithCertChain(csrPEM, s.hostnames, s.serverCertTTL, false)
    ...

	cert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
```

可以看出CA Server本身的服务器端证书也是使用内部的IstioCA来进行签发的。

最终服务器端证书会与根证书一起生成`tls.Config`对象，用于CA Server的gRPC服务中。
