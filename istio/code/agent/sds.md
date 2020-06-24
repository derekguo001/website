---
title: "第三章 SDS Server"
linkTitle: "第三章 SDS Server"
weight: 3
date: 2017-01-04
description: >
---

## 一、概述 ##

在Pilot Agent中实现了一个SDS Server，它是一个用来管理证书的组件。

{{< figure src="../sdsserver_1.png" link="../sdsserver_1.png" target="_blank" >}}

一般的使用流程如下：当前Envoy进程在与其它Envoy进程交互时，发现需要进行TLS认证，它会从静态配置文件或者动态配置服务器获取证书的名称等相关信息，这时Envoy进程就会向Pilot Agent中的SDS Server发起请求获取证书。SDS Server收到请求后，会首先读取本地的ServiceAccount Token，路径为`/var/run/secrets/kubernetes.io/serviceaccount/token`，然后从token中解析出namespace和ServiceAccount等信息，再用这些信息生成私钥和证书请求文件。接下来使用证书请求文件作为参数，向Istiod发起申请证书签名的请求。Istiod收到请求后会对其进行签名，并将签名后的数字证书和CA根证书文件一起发送给SDS Server。

## 二、模型定义 ##

{{< figure src="../sdsserver_data_1.png" link="../sdsserver_data_1.png" target="_blank" >}}

SDS Server与Envoy进行交互时的RPC接口为`SecretDiscoveryServiceServer`，通过其中的`StreamSecrets()`和`FetchSecrets()`接受请求，然后进行处理，最后将证书发送给Envoy。在Pilot Agent中实现这个接口的数据结构为`nodeagent.sds.sdsservice`，由于Envoy在Istio中可以扮演两个角色：第一个是作为普通pod的sidecar，第二个作为ingress和egress，这两种情况下处理流程是不同的，因此在实现SDS Server的时候分别进行了实现，对应的名称为`workloadSds`和`gatewaySds`，它们都作为了`nodeagent.sds.Server`的成员变量。

```
type Server struct {
	workloadSds *sdsservice
	gatewaySds  *sdsservice
    ...
}
```

为了将证书在本地进行缓存，引入了一个`SecretManager` interface。其中的`GenerateSecret()`会生成所有证书并将其缓存。

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

实际上，除了Istiod之外，还可以集成第三方的证书管理服务，比如google和aws的。因此对进行与证书管理服务交互的client也做了一层抽象，interface名为`Client`，与证书管理服务进行交互的函数为`CSRign()`。

```
type Client interface {
	CSRSign(ctx context.Context, reqID string, csrPEM []byte, subjectID string,
		certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error)
}
```

用户可以通过实现这个函数来继承`Client`这个interface。在Istio的代码中包含了几个对应的实现，包括名为`googleCAClient`的client用来与google证书管理服务交互，也包含了名称为`citadelClient`的client与Istiod内置的证书管理服务进行交互。这些client作为上文提到的`secretfetcher.SecretFetcher`的成员，SecretFetcher在进行证书签名的时候，会调用这些client。

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

另外，还有一个SDSAgent的对象，它主要用于启动上面提到的各种SDS Server相关的对象。

至此，已经将SDS Server相关的数据模型进行了串联，下面分析一下执行的具体流程。

## 三、对象的创建 ##

### SDSAgent ###

在启动Pilot Agent的过程中，会创建SDSAgent对象，并用它的`Start()`来启动

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

其中的`NewSDSAgent()`主要是做了一些变量初始化工作，主要的对象创建`Start()`中，代码如下

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


首先，根据配置判断CA的类型，如果为GoogleCA，则使用google的证书服务，会创建对应的Client。

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

否则的话，使用默认的CA，接下来判断是否配置了serverOptions.CAEndpoint，如果没有配置，则使用默认的配置，具体代码不在这里展开。

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

在默认安装Istio的情况下会对serverOptions.CAEndpoint参数进行配置，同时会启用双向TLS认证，代码会执行下面的逻辑

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

上面这段代码会根据serverOptions.PilotCertProvider进一步判断CA证书是由谁提供的，这个参数是由环境变量来配置的，在默认安装的情况下会使用指定的默认值"istiod"

```
	pilotCertProvider = env.RegisterStringVar("PILOT_CERT_PROVIDER", "istiod",
		"the provider of Pilot DNS certificate.").Get()
```

因此上面的代码会从`./var/run/secrets/istio/root-cert.pem`中读取CA内容，将其存入sa.RootCert字段中，然后创建caClient对象，并将其存入SecretFetcher的CaClient字段，代码如下

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

创建了2个sdsservice对象，分别存储于SDS Server的workloadSds和gatewaySds中，分别用于sidecar类型的envoy proxy和gateway类型的envoy proxy。
我们这里暂时只分析sidecar类型，这里的initWorkloadSdsService()仅仅是注册GRPC服务等操作。接下来会分析对于证书请求的处理过程。

## 四、请求的处理流程 ##

在概述中描述了sdsservice实现了接口为`SecretDiscoveryServiceServer`中的`StreamSecrets()`和`FetchSecrets()`函数，用来接收envoy的证书请求，接下来分析具体的实现，代码位于`security/pkg/nodeagent/sds/sdsservice.go`

### StreamSecrets ###

```
// StreamSecrets serves SDS discovery requests and SDS push requests
func (s *sdsservice) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	token := ""
	ctx := context.Background()

	var receiveError error
	reqChannel := make(chan *xdsapi.DiscoveryRequest, 1)
	con := newSDSConnection(stream)

	go receiveThread(con, reqChannel, &receiveError)
```

收到请求后`go receiveThread()`会把请求的对象发送到`reqChannel`中，然后在接下来的代码中统一处理

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

接下来回使用`GenerateSecret()`生成证书，并用`pushSDS()`将证书返回给Envoy。

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
	connKey := ConnKey{
		ConnectionID: connectionID,
		ResourceName: resourceName,
	}

	logPrefix := cacheLogPrefix(resourceName)

	// When there are existing root certificates, or private key and certificate under
	// a well known path, they are used in the SDS response.
	var err error
	var ns *model.SecretItem

	// First try to generate secret from file.
	sdsFromFile, ns, err := sc.generateFileSecret(connKey, token)

	if sdsFromFile {
		if err != nil {
			return nil, err
		}
		return ns, nil
	}

	if resourceName != RootCertReqResourceName {
		// If working as Citadel agent, send request for normal key/cert pair.
		// If working as ingress gateway agent, fetch key/cert or root cert from SecretFetcher. Resource name for
		// root cert ends with "-cacert".
		ns, err := sc.generateSecret(ctx, token, connKey, time.Now())
		if err != nil {
			cacheLog.Errorf("%s failed to generate secret for proxy: %v",
				logPrefix, err)
			return nil, err
		}

		cacheLog.Infoa("GenerateSecret ", resourceName)
		sc.secrets.Store(connKey, *ns)
		return ns, nil
	}

	// If request is for root certificate,
	// retry since rootCert may be empty until there is CSR response returned from CA.
	rootCert, rootCertExpr := sc.getRootCert()
	if rootCert == nil {
		wait := retryWaitDuration
		retryNum := 0
		for ; retryNum < maxRetryNum; retryNum++ {
			time.Sleep(wait)
			rootCert, rootCertExpr = sc.getRootCert()
			if rootCert != nil {
				break
			}

			wait *= 2
		}
	}

	if rootCert == nil {
		cacheLog.Errorf("%s failed to get root cert for proxy", logPrefix)
		return nil, errors.New("failed to get root cert")
	}

	t := time.Now()
	ns = &model.SecretItem{
		ResourceName: resourceName,
		RootCert:     rootCert,
		ExpireTime:   rootCertExpr,
		Token:        token,
		CreatedTime:  t,
		Version:      t.String(),
	}
	cacheLog.Infoa("Loaded root cert from certificate ", resourceName)
	sc.secrets.Store(connKey, *ns)
	cacheLog.Debugf("%s successfully generate secret for proxy", logPrefix)
	return ns, nil
}
```


### FetchSecrets ###

TODO
