---
title: "第二章 Istiod服务器端证书"
linkTitle: "第二章 Istiod服务器端证书"
weight: 2
date: 2017-01-04
description: >
---

## 概述 ##

Istiod内部的CA Server除了像前文提到的那样会给SDS Server提供证书签名功能之外，同时还会为Istiod内部的服务的证书进行签名，具体包括以下几个服务

- CA Server自身的服务器端证书
- Istiod服务本身的服务器端证书
- Istiod的WebHook服务的服务器端证书
- Istiod内部的DNS服务的服务器端证书

注意对于内部的这些服务的证书进行签名并非通过gRPC API，而是直接在内部调用函数进行的。另外还需要注意的是这些操作都是在CA Server自身`Run()`之前执行的，因此仅从这一点来讲也不可能通过gRPC API调用进行。

根据这些线索，可以大致勾勒出Istiod中相关服务的总体框架

代码位于`pilot/pkg/bootstrap/server.go:NewServer()`中

``` go
	// CA signing certificate must be created first.
	if args.TLSOptions.CaCertFile == "" && s.EnableCA() {
        ...
		s.ca, err = s.createCA(corev1, caOpts)
        ...
	}


	if err := s.initSecureGrpcListener(args); err != nil {
        ...
	}

	if err := s.initHTTPSWebhookServer(args); err != nil {
        ...
	}

    ...

	if dns.DNSAddr.Get() != "" {
		if err := s.initDNSTLSListener(dns.DNSAddr.Get(), args.TLSOptions); err != nil {
        ...
        }
        ..
	}

	if s.ca != nil {
		s.addStartFunc(func(stop <-chan struct{}) error {
			s.RunCA(s.secureGrpcServer, s.ca, caOpts)
			return nil
		})
    ...
    }
```

执行的步骤如下：

1. 使用`createCA()`创建CA Server
2. 使用`initSecureGrpcListener()`初始化Istiod服务，
3. 使用`initHTTPSWebhookServer()`初始化WebHook服务
4. 使用`initDNSTLSListener()`初始化DNS服务
5. 使用`RunCA()`运行ca服务

其中的2、3、4步中都会包括相应服务的服务器端证书相关操作，并且代码逻辑是完全相同的，因此我们接下来就以Istiod服务为例来进行分析。分析完Istiod的证书操作，下一章会再针对第1步和第5步，详细分析CA Server的内部逻辑。

## Istiod服务的服务器端证书 ##

Istiod服务的初始化代码位于`initSecureGrpcListener()`中

``` go
func (s *Server) initSecureGrpcListener(args *PilotArgs) error {
    ...

	err = s.initDNSCerts(host, features.IstiodServiceCustomHost.Get(), args.Namespace)
    ...
	err = s.initSecureGrpcServer(port, args.KeepaliveOptions, args.TLSOptions)
    ...

	return nil
}
```

其中`initDNSCerts()`会把各种证书写入到对应的文件中，然后在`initSecureGrpcServer()`中会读取这些文件再对服务进行相应的初始化。先来看`initDNSCerts()`

### initDNSCerts ###

``` go
// initDNSCerts will create the certificates to be used by Istiod GRPC server and webhooks.
...
func (s *Server) initDNSCerts(hostname, customHost, namespace string) error {
    ...
	var certChain, keyPEM []byte

	if features.PilotCertProvider.Get() == KubernetesCAProvider {
		log.Infof("Generating K8S-signed cert for %v", names)
		certChain, keyPEM, _, err = chiron.GenKeyCertK8sCA(s.kubeClient.CertificatesV1beta1().CertificateSigningRequests(),
			strings.Join(names, ","), parts[0]+".csr.secret", parts[1], defaultCACertPath)

		s.caBundlePath = defaultCACertPath
	} else if features.PilotCertProvider.Get() == IstiodCAProvider {
		log.Infof("Generating istiod-signed cert for %v", names)
		certChain, keyPEM, err = s.ca.GenKeyCert(names, SelfSignedCACertTTL.Get())
        ...
	} else {
		log.Infof("User specified cert provider: %v", features.PilotCertProvider.Get())
		return nil
	}
    ...

	// Save the certificates to ./var/run/secrets/istio-dns - this is needed since most of the code we currently
	// use to start grpc and webhooks is based on files. This is a memory-mounted dir.
	if err := os.MkdirAll(dnsCertDir, 0700); err != nil {
		return err
	}
	err = ioutil.WriteFile(dnsKeyFile, keyPEM, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(dnsCertFile, certChain, 0600)
	if err != nil {
		return err
	}
	log.Infoa("DNS certificates created in ", dnsCertDir)
	return nil
}
```

这个函数会根据环境变量`PILOT_CERT_PROVIDER`的配置，分几种不同的情况来生成证书

1. `kubernetes`，会使用Istiod内部的一个名为`chiron`的组件，与Kubernetes API Server通信，使用Kubernetes的CA来签发证书，具体的操作可以查看官方文档 [Istio DNS Certificate Management](https://istio.io/latest/docs/tasks/security/cert-management/dns-cert/)
2. `istiod`，这是默认值，这种情况下，会使用istiod内部的CA Server来签发证书。

生成了私钥和证书之后，会写入对应的文件中，`/var/run/secrets/istio-dns/key.pem`和`/var/run/secrets/istio-dns/cert-chain.pem`

### initSecureGrpcServer ###

接下来分析`initSecureGrpcServer()`，它会读取这些证书文件，然后初始化Istiod gRPC服务

```
func (s *Server) initSecureGrpcServer(port string, keepalive *istiokeepalive.Options, tlsOptions TLSOptions) error {
	certDir := dnsCertDir

	key := model.GetOrDefault(tlsOptions.KeyFile, path.Join(certDir, constants.KeyFilename))
	cert := model.GetOrDefault(tlsOptions.CertFile, path.Join(certDir, constants.CertChainFilename))

	certP, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}

	cp := x509.NewCertPool()
	var rootCertBytes []byte
	if tlsOptions.CaCertFile != "" {
		rootCertBytes, err = ioutil.ReadFile(tlsOptions.CaCertFile)
		if err != nil {
			return err
		}
	} else {
		rootCertBytes = s.ca.GetCAKeyCertBundle().GetRootCertPem()
	}

	cp.AppendCertsFromPEM(rootCertBytes)

	cfg := &tls.Config{
		Certificates: []tls.Certificate{certP},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    cp,
	}

	tlsCreds := credentials.NewTLS(cfg)
    ...
	opts = append(opts, grpc.Creds(tlsCreds))

	s.secureGrpcServer = grpc.NewServer(opts...)
	s.EnvoyXdsServer.Register(s.secureGrpcServer)
    ...
}
```

这个函数会从文件中读取对应的文件，包括三种：服务器私钥、服务器证书和根证书，然后生成`tls.Config`对象，再进行gRPC服务的初始化。

在读取这3个文件时，会首先尝试从命令行选项读取

``` go
	// Use TLS certificates if provided.
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.TLSOptions.CaCertFile, "caCertFile", "",
		"File containing the x509 Server CA Certificate")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.TLSOptions.CertFile, "tlsCertFile", "",
		"File containing the x509 Server Certificate")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.TLSOptions.KeyFile, "tlsKeyFile", "",
		"File containing the x509 private key matching --tlsCertFile")
```

如果用户在启动Istiod服务的时候通过命令行参数指定了证书文件，就会优先使用，否则才会读取刚才在上一个函数中保存的私钥和证书文件。

另外，如果用户没有提供根证书的话，会通过CA Server获取根证书。

以上就是Istiod gRPC服务在初始化过程中证书相关的操作，WebHook、DNS服务的初始化过程基本上是一样的，在此不再赘述。

下一章会分析CA Server的创建和运行。
