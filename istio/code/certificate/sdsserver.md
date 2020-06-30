---
title: "第三章 SDS Server"
linkTitle: "第三章 SDS Server"
weight: 3
date: 2017-01-04
description: >
---

## 一、模型定义 ##

{{< figure src="../sdsserver_data_1.png" link="../sdsserver_data_1.png" target="_blank" >}}


说明：上图中很多对象都是在nodeagent里定义，原因是在之前的版本中，nodeagent独立于Pilot Agent存在，现在nodeagent已经被合并到了Pilot Agent内部，但核心代码的实现仍然在nodeagent目录中。

Pilot Agent启动时，会创建一个SDSAgent的对象，然后执行它的`Start()`，其它SDS相关对象的创建和启动都是在`SDSAgent.Start()`内部完成的。

SDS Server与Envoy通过SDS API进行交互时的需要实现的接口为`SecretDiscoveryServiceServer`，SDS Server实现其中的`StreamSecrets()`和`FetchSecrets()`，这两个函数接受请求，然后进行处理，最后将证书发送给Envoy。在Pilot Agent中实现这个接口的数据结构为`nodeagent.sds.sdsservice`，由于Envoy在Istio中可以扮演两个角色：第一个是作为普通pod的sidecar，第二个作为ingress gateway或者egress gateway，这两种情况下处理流程是不同的，因此在实现SDS Server的时候分别进行了实现，对应的名称为`workloadSds`和`gatewaySds`，它们都作为了`nodeagent.sds.Server`的成员变量，而`nodeagent.sds.Server`就是真正的SDS Server。

```
type Server struct {
	workloadSds *sdsservice
	gatewaySds  *sdsservice
    ...
}
```

为了将证书在本地进行缓存，引入了一个`SecretManager` interface。例如其中的`GenerateSecret()`会生成所有证书并将其缓存。

```
type SecretManager interface {
	GenerateSecret(ctx context.Context, connectionID, resourceName, token string) (*model.SecretItem, error)
	SecretExist(connectionID, resourceName, token, version string) bool
	DeleteSecret(connectionID, resourceName string)
    ...
}
```

`SecretManager` interface本身会作为刚才提到的sdsservice对象一个成员，通过这种方式与SDS Server关联起来。

```
type sdsservice struct {
	st cache.SecretManager
    ...
}
```

一个名为`SecretCache`的struct实现了`SecretManager`，也就实现了`SecretManager`这个interface中的所有函数。

`SecretCache`的struct内包含了一个名为`fetcher`的成员，它的类型是`*secretfetcher.SecretFetcher`，`SecretCache`就是通过`fetcher`来与Istiod进行证书签名等操作的。

```
type SecretCache struct {
	fetcher        *secretfetcher.SecretFetcher
    ...
}
```

实际上，除了Istiod之外，还可以集成第三方的CA服务，比如google。因此对进行与CA服务交互的client也做了一层抽象，interface名为`Client`，与CA服务进行交互的函数为`CSRign()`。

```
type Client interface {
	CSRSign(ctx context.Context, reqID string, csrPEM []byte, subjectID string,
		certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error)
}
```

用户可以通过实现这个函数来继承`Client`这个interface。在Istio的代码中包含了几个对应的实现，包括名为`googleCAClient`的client用来与google CA服务交互，也包含了名称为`citadelClient`的client与Istiod内置的CA服务进行交互。这些client作为上文提到的`secretfetcher.SecretFetcher`的成员，SecretFetcher在进行证书签名的时候，会调用这些client。

```
type SecretFetcher struct {
    ...
	CaClient    caClientInterface.Client
    ...
}
```

除了通过SDS Server接受Envoy请求，然后向Istiod发送请求进行签名之外，还有另外一种情况，即证书发生变化后主动向Envoy推送配置，因此在SecretCache结构中包含了一个回调函数的成员`notifyCallback`。

```
type SecretCache struct {
    ...
	fetcher        *secretfetcher.SecretFetcher
    ...
	// callback function to invoke when detecting secret change.
	notifyCallback func(connKey ConnKey, secret *model.SecretItem) error
    ...
}
```

至此，已经将SDS Server相关的数据模型进行了串联，下面分析一下执行的具体流程。

## 二、对象的创建 ##

### SDSAgent ###

在启动Pilot Agent的过程中，首先会创建SDSAgent对象，并执行它的`Start()`

```
	proxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "Envoy proxy agent",
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},
		RunE: func(c *cobra.Command, args []string) error {
            ...
			sa := istio_agent.NewSDSAgent(proxyConfig.DiscoveryAddress, proxyConfig.ControlPlaneAuthPolicy == meshconfig.AuthenticationPolicy_MUTUAL_TLS,
				pilotCertProvider, jwtPath, outputKeyCertToDir, clusterIDVar.Get())

            ...
			// Start in process SDS.
			_, err = sa.Start(role.Type == model.SidecarProxy, podNamespaceVar.Get())
			if err != nil {
				log.Fatala("Failed to start in-process SDS", err)
			}
    ...


```

其中的`NewSDSAgent()`主要是做了一些变量初始化工作，主要的对象创建都在`Start()`中，代码如下

```
func (sa *SDSAgent) Start(isSidecar bool, podNamespace string) (*sds.Server, error) {
    ...
	workloadSecretCache, _ := sa.newSecretCache(serverOptions)
    ...
	server, err := sds.NewServer(serverOptions, workloadSecretCache, gatewaySecretCache)
    ...
	return server, nil
}
```

在`Start()`中首先创建了SecretCache对象，然后再用它作为参数去创建SDS Server对象。

先看SecretCache对象的创建

### SecretCache ###

在`newSecretCache()`中实现

```
// newSecretCache creates the cache for workload secrets and/or gateway secrets.
func (sa *SDSAgent) newSecretCache(serverOptions sds.Options) (workloadSecretCache *cache.SecretCache, caClient caClientInterface.Client) {
	ret := &secretfetcher.SecretFetcher{}

	// TODO: get the MC public keys from pilot.
	// In node agent, a controller is used getting 'istio-security.istio-system' config map
	// Single caTLSRootCert inside.

	var err error
```


首先，根据配置判断CA的类型，如果为GoogleCA，则使用google的CA服务，会创建对应的Client。

```
	// TODO: this should all be packaged in a plugin, possibly with optional compilation.
	log.Infof("serverOptions.CAEndpoint == %v", serverOptions.CAEndpoint)
	if (serverOptions.CAProviderName == "GoogleCA" || strings.Contains(serverOptions.CAEndpoint, "googleapis.com")) &&
		stsclient.GKEClusterURL != "" {
		// Use a plugin to an external CA - this has direct support for the K8S JWT token
		// This is only used if the proper env variables are injected - otherwise the existing Citadel or Istiod will be
		// used.
		caClient, err = gca.NewGoogleCAClient(serverOptions.CAEndpoint, true)
		serverOptions.PluginNames = []string{"GoogleTokenExchange"}
	} else {
```

否则的话，使用默认的CA，即Istiod中实现的CA Server，接下来判断是否配置了serverOptions.CAEndpoint，如果没有配置，则使用默认的配置，具体代码不在这里展开。

```
		// Determine the default CA.
		// If /etc/certs exists - it means Citadel is used (possibly in a mode to only provision the root-cert, not keys)
		// Otherwise: default to istiod
		//
		// If an explicit CA is configured, assume it is mounting /etc/certs
		var rootCert []byte

		tls := true
		certReadErr := false

		if serverOptions.CAEndpoint == "" {
            ...
		} else {
```

在默认安装Istio的情况下会对serverOptions.CAEndpoint参数(环境变量`CA_ADDR`)配置为`istiod.istio-system.svc:15012`，同时会启用双向TLS认证，下面是sidecar的配置

```
    - args:
        - proxy
        - sidecar
        - --domain
        ...
      env:
        ...
        - name: PILOT_CERT_PROVIDER
          value: istiod
        - name: CA_ADDR
          value: istiod.istio-system.svc:15012
```

代码会执行下面的逻辑

```
			// Explicitly configured CA
			log.Infoa("Using user-configured CA ", serverOptions.CAEndpoint)
			if strings.HasSuffix(serverOptions.CAEndpoint, ":15010") {
				log.Warna("Debug mode or IP-secure network")
				tls = false
			} else if serverOptions.TLSEnabled {
				if serverOptions.PilotCertProvider == "istiod" {
					log.Info("istiod uses self-issued certificate")
					if rootCert, err = ioutil.ReadFile(path.Join(CitadelCACertPath, constants.CACertNamespaceConfigMapDataName)); err != nil {
						certReadErr = true
					} else {
						log.Infof("the CA cert of istiod is: %v", string(rootCert))
					}
				} else if serverOptions.PilotCertProvider == "kubernetes" {
					log.Infof("istiod uses the k8s root certificate %v", k8sCAPath)
					if rootCert, err = ioutil.ReadFile(k8sCAPath); err != nil {
						certReadErr = true
					}
				} else if serverOptions.PilotCertProvider == "custom" {
					log.Infof("istiod uses a custom root certificate mounted in a well known location %v",
						cache.DefaultRootCertFilePath)
					if rootCert, err = ioutil.ReadFile(cache.DefaultRootCertFilePath); err != nil {
						certReadErr = true
					}
				} else {
					log.Errorf("unknown cert provider %v", serverOptions.PilotCertProvider)
					certReadErr = true
				}
				if certReadErr {
					rootCert = nil
					log.Fatal("invalid config - port 15012 missing a root certificate")
				}
			}
            ...
		}
```

上面这段代码会根据serverOptions.PilotCertProvider进一步判断根证书是由谁提供的，这个参数是由环境变量来配置的，在默认安装的情况下会使用指定的默认值"istiod"，详细可参考概述中SDS Server控制面证书一节的内容。

```
	pilotCertProvider = env.RegisterStringVar("PILOT_CERT_PROVIDER", "istiod",
		"the provider of Pilot DNS certificate.").Get()
```

因此在默认使用`istiod`类型的情况下，上面的代码会从`./var/run/secrets/istio/root-cert.pem`中读取根证书内容，将其存入sa.RootCert字段中，然后创建caClient对象，并将其存入SecretFetcher的CaClient字段，代码如下

```
		sa.RootCert = rootCert
		// Will use TLS unless the reserved 15010 port is used ( istiod on an ipsec/secure VPC)
		// rootCert may be nil - in which case the system roots are used, and the CA is expected to have public key
		// Otherwise assume the injection has mounted /etc/certs/root-cert.pem
		caClient, err = citadel.NewCitadelClient(serverOptions.CAEndpoint, tls, rootCert, serverOptions.ClusterID)
		if err == nil {
			sa.CitadelClient = caClient
		}
	}
```

最后，会创建SecretCache对象，然后将其存入SDSAgent.WorkloadSecrets中。

```
	if err != nil {
		log.Errorf("failed to create secretFetcher for workload proxy: %v", err)
		os.Exit(1)
	}
	ret.UseCaClient = true
	ret.CaClient = caClient

	workloadSdsCacheOptions.TrustDomain = serverOptions.TrustDomain
	workloadSdsCacheOptions.Pkcs8Keys = serverOptions.Pkcs8Keys
	workloadSdsCacheOptions.ECCSigAlg = serverOptions.ECCSigAlg
	workloadSdsCacheOptions.Plugins = sds.NewPlugins(serverOptions.PluginNames)
	workloadSdsCacheOptions.OutputKeyCertToDir = serverOptions.OutputKeyCertToDir
	workloadSecretCache = cache.NewSecretCache(ret, sds.NotifyProxy, workloadSdsCacheOptions)
	sa.WorkloadSecrets = workloadSecretCache
	return
}
```

上面的流程是在SDSAgent.Start()中完成了SecretCache对象的创建

```
func (sa *SDSAgent) Start(isSidecar bool, podNamespace string) (*sds.Server, error) {
    ...
	workloadSecretCache, _ := sa.newSecretCache(serverOptions)
    ...
	server, err := sds.NewServer(serverOptions, workloadSecretCache, gatewaySecretCache)
    ...
	return server, nil
}
```

接下来分析SDS Server的创建和启动过程，创建和启动流程都在`sds.NewServer()`

### SDS Server ###

```
func NewServer(options Options, workloadSecretCache, gatewaySecretCache cache.SecretManager) (*Server, error) {
	s := &Server{
		workloadSds: newSDSService(workloadSecretCache, false, options.UseLocalJWT,
			options.RecycleInterval, options.JWTPath, options.OutputKeyCertToDir),
		gatewaySds: newSDSService(gatewaySecretCache, true, options.UseLocalJWT,
			options.RecycleInterval, options.JWTPath, options.OutputKeyCertToDir),
	}
	if options.EnableWorkloadSDS {
		if err := s.initWorkloadSdsService(&options); err != nil {
			sdsServiceLog.Errorf("Failed to initialize secret discovery service for workload proxies: %v", err)
			return nil, err
		}
		sdsServiceLog.Infof("SDS gRPC server for workload UDS starts, listening on %q \n", options.WorkloadUDSPath)
	}

	if options.EnableIngressGatewaySDS {
		if err := s.initGatewaySdsService(&options); err != nil {
			sdsServiceLog.Errorf("Failed to initialize secret discovery service for ingress gateway: %v", err)
			return nil, err
		}
		sdsServiceLog.Infof("SDS gRPC server for ingress gateway controller starts, listening on %q \n",
			options.IngressGatewayUDSPath)
	}
    ...
	return s, nil
}
```

创建了2个sdsservice对象，分别存储于SDS Server的workloadSds和gatewaySds中，分别用于sidecar类型的envoy proxy和gateway类型的envoy proxy，创建的过程也非常简单。接着会调用`initWorkloadSdsService()`，这个函数仅仅是注册gRPC服务等操作。

截止目前，所有的对象都已经创建完成，接下来会分析对于证书请求的处理过程。

## 三、请求的处理流程 ##

在第一部分中描述了sdsservice实现了`SecretDiscoveryServiceServer`接口，主要是`StreamSecrets()`和`FetchSecrets()`这两个函数(只是使用方式不同，这两个函数的主体逻辑是一样的，这里只分析第一个函数)，用来接收envoy的证书请求，接下来分析具体的实现，代码位于`security/pkg/nodeagent/sds/sdsservice.go`

```
// StreamSecrets serves SDS discovery requests and SDS push requests
func (s *sdsservice) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
    ...
	go receiveThread(con, reqChannel, &receiveError)

	for {
		select {
		case discReq, ok := <-reqChannel:
            ...
			secret, err := s.st.GenerateSecret(ctx, conID, resourceName, token)
            ...
			if err := pushSDS(con); err != nil {
				sdsServiceLog.Errorf("%s Close connection. Failed to push key/cert to proxy %q: %v",
					conIDresourceNamePrefix, discReq.Node.Id, err)
				return err
			}
		case <-con.pushChannel:
            ...
			if err := pushSDS(con); err != nil {
				sdsServiceLog.Errorf("%s Close connection. Failed to push key/cert to proxy %q: %v",
					conIDresourceNamePrefix, proxyID, err)
				return err
			}
		}
	}
}
```

这是这个函数整体的框架，收到请求后`go receiveThread()`会把请求的对象发送到`reqChannel`中，然后在接下来的代码中统一处理

```
	var node *core.Node
	for {
		// Block until a request is received.
		select {
		case discReq, ok := <-reqChannel:
            ...
		case <-con.pushChannel:
            ...
		}
	}
}
```

在select中会监听2个channel，分别处理客户端主动发起的请求，以及证书发生变化的情况下主动推送给客户证书的情况。

### 响应客户端请求 ###

先来看第一种，在第一次接受到Envoy的请求后，会进行一些初始化工作，将当前的连接加入到一个全局的map结构中

```
			if con.conID == "" {
				// first request
				if discReq.Node == nil || len(discReq.Node.Id) == 0 {
					sdsServiceLog.Errorf("%s close connection. Missing Node ID in the first request",
						sdsLogPrefix(resourceName))
					return fmt.Errorf("missing Node ID in the first request")
				}
				con.conID = constructConnectionID(discReq.Node.Id)
				con.proxyID = discReq.Node.Id
				con.ResourceName = resourceName
				key := cache.ConnKey{
					ResourceName: resourceName,
					ConnectionID: con.conID,
				}
				addConn(key, con)
				firstRequestFlag = true
				sdsServiceLog.Infof("%s new connection", sdsLogPrefix(resourceName))
			}
```


```
func addConn(k cache.ConnKey, conn *sdsConnection) {
	sdsClientsMutex.Lock()
	defer sdsClientsMutex.Unlock()
	conIDresourceNamePrefix := sdsLogPrefix(k.ResourceName)
	sdsServiceLog.Debugf("%s add a new connection", conIDresourceNamePrefix)
	sdsClients[k] = conn
}
```

接下来会读取ServiceAccount Token，下面代码中的`s.jwtPath`会被初始化为`/var/run/secrets/kubernetes.io/serviceaccount/token`

```
			if s.localJWT {
				// Running in-process, no need to pass the token from envoy to agent as in-context - use the file
				tok, err := ioutil.ReadFile(s.jwtPath)
				if err != nil {
					sdsServiceLog.Errorf("Failed to get credential token: %v", err)
					return err
				}
				token = string(tok)
			} else if s.outputKeyCertToDir != "" {
				// Using existing certs and the new SDS - skipToken case is for the old node agent.
			} else if !s.skipToken {
				ctx = stream.Context()
				t, err := getCredentialToken(ctx)
				if err != nil {
					sdsServiceLog.Errorf("%s Close connection. Failed to get credential token from "+
						"incoming request: %v", conIDresourceNamePrefix, err)
					return err
				}
				token = t
			}
```

然后使用`GenerateSecret()`生成证书，并用`pushSDS()`将证书返回给Envoy。

```
			secret, err := s.st.GenerateSecret(ctx, conID, resourceName, token)
            ...
			if err := pushSDS(con); err != nil {
				sdsServiceLog.Errorf("%s Close connection. Failed to push key/cert to proxy %q: %v",
					conIDresourceNamePrefix, discReq.Node.Id, err)
				return err
			}
```

生成证书的核心逻辑在`GenerateSecret()`中

```
func (sc *SecretCache) GenerateSecret(ctx context.Context, connectionID, resourceName, token string) (*model.SecretItem, error) {
    ...
	// First try to generate secret from file.
	sdsFromFile, ns, err := sc.generateFileSecret(connKey, token)

	if sdsFromFile {
        ...
		return ns, nil
	}

	if resourceName != RootCertReqResourceName {
		ns, err := sc.generateSecret(ctx, token, connKey, time.Now())
        ...
		return ns, nil
	}

    ...
	rootCert, rootCertExpr := sc.getRootCert()
    ...

	ns = &model.SecretItem{
		ResourceName: resourceName,
		RootCert:     rootCert,
		ExpireTime:   rootCertExpr,
		Token:        token,
		CreatedTime:  t,
		Version:      t.String(),
	}
    ...
	return ns, nil
}
```

这个函数主体分为三个部分：

1. 首先从文件中读取，如果成功，则立即返回，执行函数为`generateFileSecret()`，会从`/etc/certs/`目录下读取证书文件，这就是概述一节中SDS Server手动注入数据面证书的内容对应的代码。如果执行成功，说明证书文件是手动注入的，这时再添加一个watch file的操作，持续监控证书文件，如果证书文件发生变化，则重新主动推送，详见下一节的内容。
2. 如果从文件中读取失败，说明证书需要动态生成，这时会首先判断客户端请求的证书是不是根证书，如果不是，则执行`generateSecret()`生成证书，然后返回。
3. 如果客户端请求的是根证书，则用`getRootCert()`获取根证书后返回。注意这一步获取的根证书也在刚才提到的`generateSecret()`中生成并保存的。

从第2、3种情况中可以看出，代码核心逻辑在`generateSecret()`中，下面来详细分析这个函数

```
func (sc *SecretCache) generateSecret(ctx context.Context, token string, connKey ConnKey, t time.Time) (*model.SecretItem, error) {
    ...
	exchangedToken, err := sc.getExchangedToken(ctx, token, connKey)
```

可以看出，首先使用token等信息生成一个exchange token

```
    ...
	options := pkiutil.CertOptions{
		Host:       csrHostName,
		RSAKeySize: keySize,
		PKCS8Key:   sc.configOptions.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(sc.configOptions.ECCSigAlg),
	}

	csrPEM, keyPEM, err := pkiutil.GenCSR(options)
    ...
```

然后使用`GenCSR()`生成私钥和证书签名请求文件。

```
	certChainPEM, err := sc.sendRetriableRequest(ctx, csrPEM, exchangedToken, connKey, true)
```

接着使用exchange token和私钥、证书签名请求文件等信息向Istiod中的CA Server发起证书签名请求。返回结果是签名后的证书。

```
	certChain := []byte{}
	for _, c := range certChainPEM {
		certChain = append(certChain, []byte(c)...)
	}

    ...
	rootCert, _ := sc.getRootCert()
	// Leaf cert is element '0'. Root cert is element 'n'.
	rootCertChanged := !bytes.Equal(rootCert, []byte(certChainPEM[length-1]))
	if rootCert == nil || rootCertChanged {
		rootCertExpireTime, err := nodeagentutil.ParseCertAndGetExpiryTimestamp([]byte(certChainPEM[length-1]))
		if err == nil {
			sc.setRootCert([]byte(certChainPEM[length-1]), rootCertExpireTime)
		} else {
			cacheLog.Errorf("%s failed to parse root certificate in CSR response: %v", logPrefix, err)
			rootCertChanged = false
		}
	}

	if rootCertChanged {
		cacheLog.Info("Root cert has changed, start rotating root cert for SDS clients")
		sc.rotate(true /*updateRootFlag*/)
	}
```

这一段代码的含义是从签名后的证书中获取根证书，并和本地保存的根证书进行比较，如果结果不同或者本地没有根证书(发生在服务第一次的时候)，则使用新的根证书重设本地的根证书，并且当根证书发生改变之后，会通过`rotate()`轮换证书，即向客户端主动推送根证书。

```
	return &model.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     connKey.ResourceName,
		Token:            token,
		CreatedTime:      t,
		ExpireTime:       expireTime,
		Version:          t.Format("01-02 15:04:05.000"), // Precise enough version based on creation time.
	}, nil
}
```

最后将私钥和根证书以及token等信息返回。

截止目前已经分析了SDS Server接受客户端请求并进行相应的整个过程，除了这种形式之外，SDS Server检测到证书发生改变之后，还会向客户端主动推送，这是下一节的内容。

### 主动推送 ###

我们现在回到`StreamSecrets()`中，上一节讲述了相应客户端请求的情况，本节详细分析一下主动推送的情况

```
	var node *core.Node
	for {
		// Block until a request is received.
		select {
		case discReq, ok := <-reqChannel:
            ...
		case <-con.pushChannel:
			con.mutex.RLock()
			proxyID := con.proxyID
			conID := con.conID
			resourceName := con.ResourceName
			secret := con.secret
			con.mutex.RUnlock()

			if secret == nil {
                ...
			}

			if err := pushSDS(con); err != nil {
				sdsServiceLog.Errorf("%s Close connection. Failed to push key/cert to proxy %q: %v",
					conIDresourceNamePrefix, proxyID, err)
				return err
			}
		}
	}
}
```

可以看出，主动推送是通过`pushChannel`进行的，而且仅仅做一些错误检测，就直接执行`pushSDS()`了，因此说明在通过`pushChannel`接受到消息之前，`conn`对象已经包含了要发送的证书信息。

一般这种通过回调函数执行的情况只需要关注两个地方

1. 回调函数的注册
2. 回调函数的触发

我们首先看一下回调函数的注册，在创建`SecretCache`对象的时候

```
func (sa *SDSAgent) newSecretCache(serverOptions sds.Options) (workloadSecretCache *cache.SecretCache, caClient caClientInterface.Client) {
    ...
	workloadSecretCache = cache.NewSecretCache(ret, sds.NotifyProxy, workloadSdsCacheOptions)
	sa.WorkloadSecrets = workloadSecretCache
	return
}
```

注意`NewSecretCache()`的第二个参数其实就是回调函数

```
func NotifyProxy(connKey cache.ConnKey, secret *model.SecretItem) error {
	conIDresourceNamePrefix := sdsLogPrefix(connKey.ResourceName)

	conn := sdsClients[connKey]
    ...
	conn.mutex.Lock()
	conn.secret = secret
	conn.mutex.Unlock()
	sdsClientsMutex.Unlock()

	conn.pushChannel <- &sdsEvent{}
	return nil
}
```

可以看出这个回调函数只是将`secret`(包含了私钥和根证书等信息)存到`conn`中，然后给`pushChannel`发送一个通知消息。

将回调函数作为参数传递给`NewSecretCache()`后，内部会将回调函数保存到`SecretCache.notifyCallback`成员中。

至此，回调函数的注册就结束了，接下来看如何触发这个回调函数。

通过跟踪`SecretCache.notifyCallback`这个成员变量，发现它只使用在了一个地方

```
func (sc *SecretCache) callbackWithTimeout(connKey ConnKey, secret *model.SecretItem) {
	go func() {
        ...
		if err := sc.notifyCallback(connKey, secret); err != nil {
            ...
		}
	}()
	select {
	case <-c:
		return // completed normally
	case <-time.After(notifySecretRetrievalTimeout):
		cacheLog.Warnf("%s notify secret change for proxy got timeout", logPrefix)
	}
}
```

触发这个回调函数实际上就是通过调用`callbackWithTimeout()`来实现的，主要有两个地方对其进行调用

上一节分析SDS Server相应客户端请求的时候提到了如果发现有用户手动插入的证书，会优先使用，相关代码在`generateFileSecret()`中

```
func (sc *SecretCache) generateFileSecret(connKey ConnKey, token string) (bool, *model.SecretItem, error) {
    ...
	switch {
	// Default root certificate.
	case connKey.ResourceName == RootCertReqResourceName && sc.rootCertificateExist(sc.existingRootCertFile):
		sdsFromFile = true
		ns, err = sc.generateRootCertFromExistingFile(sc.existingRootCertFile, token, connKey)
		sc.addFileWatcher(sc.existingRootCertFile, token, connKey)
	// Default workload certificate.
	case connKey.ResourceName == WorkloadKeyCertResourceName && sc.keyCertificateExist(sc.existingCertChainFile, sc.existingKeyFile):
		sdsFromFile = true
		ns, err = sc.generateKeyCertFromExistingFiles(sc.existingCertChainFile, sc.existingKeyFile, token, connKey)
		// Adding cert is sufficient here as key can't change without changing the cert.
		sc.addFileWatcher(sc.existingCertChainFile, token, connKey)
	default:
		// Check if the resource name refers to a file mounted certificate.
		// Currently used in destination rules and server certs (via metadata).
		// Based on the resource name, we need to read the secret from a file encoded in the resource name.
		cfg, ok := pilotmodel.SdsCertificateConfigFromResourceName(connKey.ResourceName)
		switch {
		case ok && cfg.IsRootCertificate() && sc.rootCertificateExist(cfg.CaCertificatePath):
			sdsFromFile = true
			ns, err = sc.generateRootCertFromExistingFile(cfg.CaCertificatePath, token, connKey)
			sc.addFileWatcher(cfg.CaCertificatePath, token, connKey)
		case ok && cfg.IsKeyCertificate() && sc.keyCertificateExist(cfg.CertificatePath, cfg.PrivateKeyPath):
			sdsFromFile = true
			ns, err = sc.generateKeyCertFromExistingFiles(cfg.CertificatePath, cfg.PrivateKeyPath, token, connKey)
			// Adding cert is sufficient here as key can't change without changing the cert.
			sc.addFileWatcher(cfg.CertificatePath, token, connKey)
		}
	}
    ...
	return sdsFromFile, nil, nil
}
```

可以看到这个函数里面有很多`addFileWatcher()`的调用

```
func (sc *SecretCache) addFileWatcher(file string, token string, connKey ConnKey) {
    ...
	go func() {
		var timerC <-chan time.Time
		for {
			select {
			case <-timerC:
                ...
				connKeys := sc.fileCerts[npath]
                ...
				for ckey := range connKeys {
					if _, ok := sc.secrets.Load(ckey); ok {
						// Regenerate the Secret and trigger the callback that pushes the secrets to proxy.
						if _, secret, err := sc.generateFileSecret(ckey, token); err != nil {
							cacheLog.Errorf("%v: error in generating secret after file change [%s] %v", ckey, file, err)
						} else {
							cacheLog.Infof("%v: file changed, triggering secret push to proxy [%s]", ckey, file)
							sc.callbackWithTimeout(ckey, secret)
						}
					}
				}
			case e := <-sc.certWatcher.Events(file):
				if len(e.Op.String()) > 0 { // To avoid spurious events, mainly coming from tests.
					// Use a timer to debounce watch updates
					if timerC == nil {
						timerC = time.After(100 * time.Millisecond) // TODO: Make this configurable if needed.
					}
				}
			}
		}
	}()
}
```

实际上就是通过`addFileWatcher()`来watch相关的证书文件，当发现文件改变之后，会调用`callbackWithTimeout()`。

另一种情况是在证书轮换的时候，在上一节中分析到generateSecret()内部生成证书的之后，会检测新的根证书和本地缓存的证书是否一致，不一致的情况下会执行证书轮换工作

```
func (sc *SecretCache) generateSecret(ctx context.Context, token string, connKey ConnKey, t time.Time) (*model.SecretItem, error) {
    ...
	if rootCertChanged {
		cacheLog.Info("Root cert has changed, start rotating root cert for SDS clients")
		sc.rotate(true /*updateRootFlag*/)
	}

	return &model.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     connKey.ResourceName,
		Token:            token,
		CreatedTime:      t,
		ExpireTime:       expireTime,
		Version:          t.Format("01-02 15:04:05.000"), // Precise enough version based on creation time.
	}, nil
}
```

在`rotate()`中

```
func (sc *SecretCache) rotate(updateRootFlag bool) {
    ...
	sc.secrets.Range(func(k interface{}, v interface{}) bool {
        ...
		if updateRootFlag {
            ...
			sc.callbackWithTimeout(connKey, ns)

			return true
		}

        ...
		// Re-generate secret if it's expired.
		if sc.shouldRotate(&secret) {
			atomic.AddUint64(&sc.secretChangedCount, 1)
			// Send the notification to close the stream if token is expired, so that client could re-connect with a new token.
			if sc.isTokenExpired(&secret) {
                ...
				sc.callbackWithTimeout(connKey, nil /*nil indicates close the streaming connection to proxy*/)
				return true
			}

			wg.Add(1)
			go func() {
                ...
				ns, err := sc.generateSecret(context.Background(), secret.Token, connKey, now)
				if err != nil {
					cacheLog.Errorf("%s failed to rotate secret: %v", logPrefix, err)
					return
				}
                ...
				sc.callbackWithTimeout(connKey, ns)

			}()
		}

		return true
	})
    ...
}
```

可以看出在`rotate()`中会根据情况直接调用回调函数来向客户端推送新证书，或者检测到证书过期后重新生成证书，然后再次通过执行回调函数来向客户端推送证书。这是第二个执行回调函数的地方。

现在已经分析了如何SDS Server相应Envoy客户端的sds请求以及主动推送证书给客户端的情况。更多的细节请参考源代码，如发现有错误请及时联系，谢谢。
