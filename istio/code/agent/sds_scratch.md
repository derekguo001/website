# Istiod内部的ca服务 #

## 概述 ##

在Istiod内部会运行一个ca服务，用来给Pilot Agent提供颁发证书(根据证书请求文件生成证书)的作用，Pilot Agent会把收到的证书再转发给envoy。

用户可以在Istiod运行的时候使用`--tlsKeyFile`参数手动配置证书，这时就不会运行内部的ca服务。

如果用户指定证书，则这几个证书会当做Istiod服务器端证书来使用，即Istiod处理Pilot Agent或者Envoy的请求时，指定的ca证书用来验证对方身份，指定的公钥证书会发送给对方以便对方验证Istiod的身份。另外在注入sidecar时还会把私钥和公钥传递过去。

有2个函数可以用来处理Pilot Agent发送过来的CSR请求。

CreateCertificate()
HandleCSR()

第二个被标记为过时的。

一般涉及到4个证书

./etc/cacerts/ca-key.pem        ca私钥
./etc/cacerts/ca-cert.pem       ca证书
./etc/cacerts/ca-chain.pem      ca证书链
./etc/cacerts/root-cert.pem     根证书

ca证书用于给集群中的工作负载进行签名，即对Pilog Agent发起的CSR请求进行签名
ca证书和ca私钥必须由根证书签名
ca证书链是ca证书与根证书之间的信任链

## 相关的资源 ##

- istio-ca-secret secret

  位于istio-system中，用来持久化保存自签名的ca私钥和ca证书，其它字段都为空，只由Istiod使用，与Pilot Agent没有关系

- istio-ca-root-cert configmap

  每个namespace中都会有一个，用于保存根证书，会挂载到Pilot Agent的`/var/run/secrets/istio`目录

- istio-security configmap

  位于istio-system中，用来保存根证书。之前使用在nodeagent中，目前nodeagent已经集成到Pilot Agent中，根证书改为从istio-ca-root-cert configmap中获取，目前代码有注释说明保留这个只是为了向前兼容，实际上没没有实际使用，以后会从代码中完全移除

- cacerts secret

  会挂载到Istiod的`/etc/cacerts`目录，用户可以手动通过现有证书创建这个secret，然后再部署Istio，这样Istio就可以使用用户指定的证书，详见 https://istio.io/latest/docs/tasks/security/cert-management/plugin-ca-cert/


log

```
[root@master1]# kubectl get cm --all-namespaces
NAMESPACE         NAME                                   DATA   AGE
default           istio-ca-root-cert                     1      28d
foo               istio-ca-root-cert                     1      10d
istio-system      istio                                  2      13d
istio-system      istio-ca-root-cert                     1      28d
istio-system      istio-leader                           0      28d
istio-system      istio-namespace-controller-election    0      28d
istio-system      istio-security                         1      28d
istio-system      istio-sidecar-injector                 2      13d
istio-system      istio-validation-controller-election   0      28d
istio-system      prometheus                             1      13d
kube-node-lease   istio-ca-root-cert                     1      28d
kube-public       cluster-info                           1      28d
kube-public       istio-ca-root-cert                     1      28d
kube-system       coredns                                1      28d
kube-system       extension-apiserver-authentication     6      28d
kube-system       istio-ca-root-cert                     1      28d
kube-system       kube-flannel-cfg                       2      28d
kube-system       kube-proxy                             2      28d
kube-system       kubeadm-config                         2      28d
kube-system       kubelet-config-1.16                    1      28d
[root@master1]#

[root@master1]# kubectl get secret --all-namespaces | grep istio
istio-system      default-token-wgrx7                                kubernetes.io/service-account-token   3      28d
istio-system      istio-ca-secret                                    istio.io/ca-root                      5      28d
istio-system      istio-ingressgateway-service-account-token-x9jzx   kubernetes.io/service-account-token   3      13d
istio-system      istio-reader-service-account-token-lrp6c           kubernetes.io/service-account-token   3      13d
istio-system      istiod-service-account-token-97p6c                 kubernetes.io/service-account-token   3      13d
istio-system      prometheus-token-c8kgw                             kubernetes.io/service-account-token   3      13d

[root@master1 ~]# kubectl get secret istio-ca-secret -n istio-system -o yaml
apiVersion: v1
data:
  ca-cert.pem: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMzakNDQWNhZ0F3SUJBZ0lSQU5tT1pXZk1sWGZXS01qMXhxSVN1Q0l3RFFZSktvWklodmNOQVFFTEJRQXcKR0RFV01CUUdBMVVFQ2hNTlkyeDFjM1JsY2k1c2IyTmhiREFlRncweU1EQTFNalV3TnpNeE1UaGFGdzB6TURBMQpNak13TnpNeE1UaGFNQmd4RmpBVUJnTlZCQW9URFdOc2RYTjBaWEl1Ykc5allXd3dnZ0VpTUEwR0NTcUdTSWIzCkRRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQzRrRUFOam93YmJMZWY5cDIwbXhIREdEVkhoRFRaWEk5OEZsd2gKODJ5elpFaDM2MDE5ODRSayszaUhhVVJMYlBLV3c1UXNRd29nM2xVbkFzWDhCYzdSQnFhUVpXZEE5WTlCaHN0eAprUktQQlVLWTBnb3ZKaHVla3JmWk1uRllQQnlyMUpGb2NIa0V3YjF4cWJxWE0zdU12dE5ZbkJPclpsWVhqRS9oCmRNVWdqRG1mSjIwZEg2RE9pK1dTdzRsZTd1WDRnMEZBK3ZGemZnRmRSWkVsM2RHeEtOU3dBc2tpN3ZVUVpKbUUKbHFRdVlFZnhhYStBT2M3TVNlY24vMzY2eXNwQWN1ZDg5V2hHWU9SRjBhVUNVWlVXMU5ZbXJlL2RKNkFHbGFtaQpWVEgyWEFtZjltWFlWZ2N1SGlvK01JVldmMWc2U1ArTVlLY2NkS0FlWDRLM1VURnRBZ01CQUFHakl6QWhNQTRHCkExVWREd0VCL3dRRUF3SUNCREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUIKQVFCcWFWK25nUGtYOURGS0xsdk9panhnSTJnMDdFUjZrZHJhS2FRbmhIa1ZseFR2b254VDRCYXJoKzYwL0NWeApvWHRwZzc2dnZnUnFwdW5mMDhvZ3lUTmE5S0RXS2hpNlA2SkNOR2l6TldNWEdsbElCMkd2UWFIYXdQMHI5Rm8yCm5KTUMxNXJib0RLREJxSmY4anJxN2VrSXFwVFNKbExUMEVORG1yUkprb1JiMEhGWExNK29OMzUzZEFEUnkvNW0KWHllTzR0V0VNOHo0K3FobU1DYVp4b1M1VkI3Y1hUOGhFcTVBblRFM3VUQjQ5LzhETEphTGZrSjJKNHJ5V0tiOQp6eEFNcXJieW10QjNIUjBzM1U2WUJmQlg2SzBIYzdkS25kbWptSVN6RnJsR2ZjQ1g1eG9HN0tLZFpDaUIzdkRTCm9HRFUwSVk1N3BRNTRIUVExL3ZCUEJqRgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
  ca-key.pem: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdUpCQURZNk1HMnkzbi9hZHRKc1J3eGcxUjRRMDJWeVBmQlpjSWZOc3MyUklkK3ROCmZmT0VaUHQ0aDJsRVMyenlsc09VTEVNS0lONVZKd0xGL0FYTzBRYW1rR1ZuUVBXUFFZYkxjWkVTandWQ21OSUsKTHlZYm5wSzMyVEp4V0R3Y3E5U1JhSEI1Qk1HOWNhbTZsek43akw3VFdKd1RxMlpXRjR4UDRYVEZJSXc1bnlkdApIUitnem92bGtzT0pYdTdsK0lOQlFQcnhjMzRCWFVXUkpkM1JzU2pVc0FMSkl1NzFFR1NaaEpha0xtQkg4V212CmdEbk96RW5uSi85K3VzcktRSExuZlBWb1JtRGtSZEdsQWxHVkZ0VFdKcTN2M1NlZ0JwV3BvbFV4OWx3Sm4vWmwKMkZZSExoNHFQakNGVm45WU9rai9qR0NuSEhTZ0hsK0N0MUV4YlFJREFRQUJBb0lCQVFDd0tQY0tPWW5mVDBpQgpCU29Ielk4SmtOeWgwejJDVGtlaDM5RzJraHFwcTBsRU5MSjFTbTZPMkR0MXUvTDByeHRvN1dwTFNQMnMyNm1aCkg1dUxicHUxaFV5TVBFMXVnak5uRHRxMkhnc0J1YnFVRkw2bHZCRFdyU0dQelFiRWVqTy9pcGZ6Z0k3eURGM2UKMUdzRmtKMFhmTGhMTmtYTDdsUzBDemZmY000S3ZrMzJMK1MxTlpJeHhseiswRU9weWJvUXduL01GQmxXdERXcApoNnoycHYxNStmR2NyZHQ3R00vMkFvTW9iYzBEZExST2lnVFgydE4rWExlbk8yU3M4cS9sYWdGZVNwNWRQTC95CmY0TFNLTm9ZRERBb3o1VklhTnAyTytiSzVzdERGdzdxYWxiYUUwdE53Mm1lRE9uMUU1SVlkV3BoeElGaTNrT1cKcnRZQnZGY2hBb0dCQU5jNjJ2K2xFZHlQaHBlUlBJa2lKbUY5L3p2NGFXM0d2eUpKbE9TK3ovN1d1SWJVeElmNQpRZHhST2hyeko2bjhQaHhoM1o3TzNnUUY3QysvVktFa240RmhZUXNNSHphMFcybU12SWhzUEpDeDFSZ2RLSGJRCjRPMHhobHRrVmZTblFiN1RTb1ovOW8zMUNPWlkvVkVDaUExWUJpOXUwNlBGOGd3UHBaWTZFZWVKQW9HQkFOdUcKU1ovcHZqd2NZUmZJaDVXT3FDVnNhaVU0SGV0TmN1UmZxNi9OVnJvNWZYU0IvK05JMGJFYnRtZXYzN2g2R1FEOQpQdjB4UW5oZDdwcXM1L1dRTm9UdjM4VDVGZEpVWXk5dWc4T2cxN3NCK0kwSWd2YTNvQyswQXRrTnE0ZThlRnZrClhiZGdPTWtKQnBGQUd1NThJK05hNE1YaEY2U0xsRTgxaUxNNmM1M0ZBb0dBVFdQSFRUY0FsaXN4ZlJ4bkJQUTMKa3NTb1d0cjJwZGRaOEswK2tZV2U2b1l3c2FLZHpEcXZHTlpJSzFxVlA0VUluRklBUzFNYzk1dGRrc21jVjVrQQpsWmY3T2VxdzZvMnRkT1Y3QVI3U0pFRWRXMTlZcG1oekNEYlBsZHNkSVN4bThvT3MvM0hScUxlYjdKL0E3amtYCnpKeURGTmtuMW5LZGx3S2xTc0Ewb2VrQ2dZQnN5Z25tZzlIUXZFZXBuNmtCaHVieFZON3RmdmZreWticndqVzEKTTgrTkRqeUw1bmpIVENrTzJpcjFDNFdWU0h6bnJwanVwT0RLQWRMak9Gampxd281cXg1NzRPemRoUkI2U3d4bApnR29vdFB0VitTZmQySFk3N2J1VGtXQzJMY0ovMTVaUjhBOTBJVkx0M0pUOEp1MHFHTGxYbHdzK2NpV1hjM0pCClQvQkgrUUtCZ0ViR2ZFa054ZVgrbEZDU21DdnUzY3J0bVNMNFdYRzZEam9Kd25LTkVjMEVPT2R5QW9SQ25oeG4KVmZLOG90WUxzRnZwRlREQWFYV2YzdkFhQWFudmhEWStGU3R5eXB6YlZaZnVJb2VWemZhOGVZdm5qMWVtQ3lpSQpZY1hWK3RxYnhFOTBGUzk5TXFWRUJRREE1ekt0ZmhGLzBwb1hpQjNkdmVsdThOTkgxanQzCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==
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
[root@master1 ~]#

[root@master1 ~]# kubectl get cm istio-security -n istio-system -o yaml
apiVersion: v1
data:
  caTLSRootCert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMzakNDQWNhZ0F3SUJBZ0lSQU5tT1pXZk1sWGZXS01qMXhxSVN1Q0l3RFFZSktvWklodmNOQVFFTEJRQXcKR0RFV01CUUdBMVVFQ2hNTlkyeDFjM1JsY2k1c2IyTmhiREFlRncweU1EQTFNalV3TnpNeE1UaGFGdzB6TURBMQpNak13TnpNeE1UaGFNQmd4RmpBVUJnTlZCQW9URFdOc2RYTjBaWEl1Ykc5allXd3dnZ0VpTUEwR0NTcUdTSWIzCkRRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQzRrRUFOam93YmJMZWY5cDIwbXhIREdEVkhoRFRaWEk5OEZsd2gKODJ5elpFaDM2MDE5ODRSayszaUhhVVJMYlBLV3c1UXNRd29nM2xVbkFzWDhCYzdSQnFhUVpXZEE5WTlCaHN0eAprUktQQlVLWTBnb3ZKaHVla3JmWk1uRllQQnlyMUpGb2NIa0V3YjF4cWJxWE0zdU12dE5ZbkJPclpsWVhqRS9oCmRNVWdqRG1mSjIwZEg2RE9pK1dTdzRsZTd1WDRnMEZBK3ZGemZnRmRSWkVsM2RHeEtOU3dBc2tpN3ZVUVpKbUUKbHFRdVlFZnhhYStBT2M3TVNlY24vMzY2eXNwQWN1ZDg5V2hHWU9SRjBhVUNVWlVXMU5ZbXJlL2RKNkFHbGFtaQpWVEgyWEFtZjltWFlWZ2N1SGlvK01JVldmMWc2U1ArTVlLY2NkS0FlWDRLM1VURnRBZ01CQUFHakl6QWhNQTRHCkExVWREd0VCL3dRRUF3SUNCREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUIKQVFCcWFWK25nUGtYOURGS0xsdk9panhnSTJnMDdFUjZrZHJhS2FRbmhIa1ZseFR2b254VDRCYXJoKzYwL0NWeApvWHRwZzc2dnZnUnFwdW5mMDhvZ3lUTmE5S0RXS2hpNlA2SkNOR2l6TldNWEdsbElCMkd2UWFIYXdQMHI5Rm8yCm5KTUMxNXJib0RLREJxSmY4anJxN2VrSXFwVFNKbExUMEVORG1yUkprb1JiMEhGWExNK29OMzUzZEFEUnkvNW0KWHllTzR0V0VNOHo0K3FobU1DYVp4b1M1VkI3Y1hUOGhFcTVBblRFM3VUQjQ5LzhETEphTGZrSjJKNHJ5V0tiOQp6eEFNcXJieW10QjNIUjBzM1U2WUJmQlg2SzBIYzdkS25kbWptSVN6RnJsR2ZjQ1g1eG9HN0tLZFpDaUIzdkRTCm9HRFUwSVk1N3BRNTRIUVExL3ZCUEJqRgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
kind: ConfigMap
metadata:
  creationTimestamp: "2020-05-25T07:31:18Z"
  name: istio-security
  namespace: istio-system
  resourceVersion: "2449"
  selfLink: /api/v1/namespaces/istio-system/configmaps/istio-security
  uid: b98aae70-1023-4902-8098-ce1281a115c6
[root@master1 ~]#

[root@master1 ~]# kubectl get cm istio-ca-root-cert -n istio-system -o yaml
apiVersion: v1
data:
  root-cert.pem: |
    -----BEGIN CERTIFICATE-----
    MIIC3jCCAcagAwIBAgIRANmOZWfMlXfWKMj1xqISuCIwDQYJKoZIhvcNAQELBQAw
    GDEWMBQGA1UEChMNY2x1c3Rlci5sb2NhbDAeFw0yMDA1MjUwNzMxMThaFw0zMDA1
    MjMwNzMxMThaMBgxFjAUBgNVBAoTDWNsdXN0ZXIubG9jYWwwggEiMA0GCSqGSIb3
    DQEBAQUAA4IBDwAwggEKAoIBAQC4kEANjowbbLef9p20mxHDGDVHhDTZXI98Flwh
    82yzZEh3601984Rk+3iHaURLbPKWw5QsQwog3lUnAsX8Bc7RBqaQZWdA9Y9Bhstx
    kRKPBUKY0govJhuekrfZMnFYPByr1JFocHkEwb1xqbqXM3uMvtNYnBOrZlYXjE/h
    dMUgjDmfJ20dH6DOi+WSw4le7uX4g0FA+vFzfgFdRZEl3dGxKNSwAski7vUQZJmE
    lqQuYEfxaa+AOc7MSecn/366yspAcud89WhGYORF0aUCUZUW1NYmre/dJ6AGlami
    VTH2XAmf9mXYVgcuHio+MIVWf1g6SP+MYKccdKAeX4K3UTFtAgMBAAGjIzAhMA4G
    A1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB
    AQBqaV+ngPkX9DFKLlvOijxgI2g07ER6kdraKaQnhHkVlxTvonxT4Barh+60/CVx
    oXtpg76vvgRqpunf08ogyTNa9KDWKhi6P6JCNGizNWMXGllIB2GvQaHawP0r9Fo2
    nJMC15rboDKDBqJf8jrq7ekIqpTSJlLT0ENDmrRJkoRb0HFXLM+oN353dADRy/5m
    XyeO4tWEM8z4+qhmMCaZxoS5VB7cXT8hEq5AnTE3uTB49/8DLJaLfkJ2J4ryWKb9
    zxAMqrbymtB3HR0s3U6YBfBX6K0Hc7dKndmjmISzFrlGfcCX5xoG7KKdZCiB3vDS
    oGDU0IY57pQ54HQQ1/vBPBjF
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

## 数据结构 ##

security/proto/ca_service.pb.go

```
// IstioCAServiceServer is the server API for IstioCAService service.
type IstioCAServiceServer interface {
	// A request object includes a PEM-encoded certificate signing request that
	// is generated on the Node Agent. Additionally credential can be attached
	// within the request object for a server to authenticate the originating
	// node agent.
	HandleCSR(context.Context, *CsrRequest) (*CsrResponse, error)
}
```

security/proto/istioca.pb.go

```
// IstioCertificateServiceServer is the server API for IstioCertificateService service.
type IstioCertificateServiceServer interface {
	// Using provided CSR, returns a signed certificate.
	CreateCertificate(context.Context, *IstioCertificateRequest) (*IstioCertificateResponse, error)
}
```

security/pkg/server/ca/server.go

```
// Server implements IstioCAService and IstioCertificateService and provides the services on the
// specified port.
type Server struct {
	monitoring     monitoringMetrics
	Authenticators []authenticator
	hostnames      []string
	authorizer     authorizer
	ca             CertificateAuthority
	serverCertTTL  time.Duration
	certificate    *tls.Certificate
	port           int
	forCA          bool
	grpcServer     *grpc.Server
}
```



```
// Certificate response message.
type IstioCertificateResponse struct {
	// PEM-encoded certificate chain.
	// Leaf cert is element '0'. Root cert is element 'n'.
	CertChain []string `protobuf:"bytes,1,rep,name=cert_chain,json=certChain,proto3" json:"cert_chain,omitempty"`
}
```

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


// IstioCA generates keys and certificates for Istio identities.
type IstioCA struct {
	defaultCertTTL time.Duration
	maxCertTTL     time.Duration

	keyCertBundle util.KeyCertBundle

	livenessProbe *probe.Probe

	// rootCertRotator periodically rotates self-signed root cert for CA. It is nil
	// if CA is not self-signed CA.
	rootCertRotator *SelfSignedCARootCertRotator
}
```

IstioCA继承了CertificateAuthority这个interface
其中有两个参数非常重要
- keyCertBundle util.KeyCertBundle类型，把相关证书都绑定到一起，这个整体的对象提供了一些接口
- rootCertRotator *SelfSignedCARootCertRotator类型，如果是自签名证书的话这个值为空，否则是一个轮询对象，会周期性地更新相关证书

在创建IstioCA的时候会把所有的参数先整合到一起，形成一个整体的参数对象，这个对象的结构命为IstioCAOptions，实际上创建IstioCA过程很简单，就是把IstioCAOptions中的参数赋值给IstioCA对象，所以很多步骤是在创建IstioCAOptions对象的时候完成的

```
type IstioCAOptions struct {
	CAType caTypes

	DefaultCertTTL time.Duration
	MaxCertTTL     time.Duration

	KeyCertBundle util.KeyCertBundle

	LivenessProbeOptions *probe.Options
	ProbeCheckInterval   time.Duration

	// Config for creating self-signed root cert rotator.
	RotatorConfig *SelfSignedCARootCertRotatorConfig
}
```

CAType，表明IstioCA的类型，包含两种：自签名证书和用户指定证书

## 运行过程 ##

入口代码位于`pilot/pkg/bootstrap/server.go:NewServer()`中

```
	log.Infof("JWT policy is %s", features.JwtPolicy.Get())
	switch features.JwtPolicy.Get() {
	case jwt.JWTPolicyThirdPartyJWT:
		s.jwtPath = ThirdPartyJWTPath
	case jwt.JWTPolicyFirstPartyJWT:
		s.jwtPath = securityModel.K8sSAJwtFileName
	default:
		err := fmt.Errorf("invalid JWT policy %v", features.JwtPolicy.Get())
		log.Errorf("%v", err)
		return nil, err
	}

	// CA signing certificate must be created first.
	if args.TLSOptions.CaCertFile == "" && s.EnableCA() {
		var err error
		var corev1 v1.CoreV1Interface
		if s.kubeClient != nil {
			corev1 = s.kubeClient.CoreV1()
		}
		// May return nil, if the CA is missing required configs - This is not an error.
		s.ca, err = s.createCA(corev1, caOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA: %v", err)
		}
		err = s.initPublicKey()
		if err != nil {
			return nil, fmt.Errorf("error initializing public key: %v", err)
		}
	}
```

这就是ca服务主要的框架，主要分为三步：首先读取jwt token，接着创建ca，最后初始化公钥

### jwt token ###

JWT_POLICY如果不配置，则为third-party-jwt，默认安装的情况下配置为first-party-jwt，这两种情况下对应的jwt文件路径

```
	// ThirdPartyJWTPath is the well-known location of the projected K8S JWT. This is mounted on all workloads, as well as istiod.
	ThirdPartyJWTPath = "./var/run/secrets/tokens/istio-token"

	// K8sSAJwtFileName is the token volume mount file name for k8s jwt token.
	K8sSAJwtFileName = "/var/run/secrets/kubernetes.io/serviceaccount/token"
```

这里的`third`是指第三方，例如google的云服务配置的路径。下面的代码片段来自于`manifests/charts/istio-control/istio-discovery/files/gen-istio.yaml`

```
        volumeMounts:
        {{- if eq .Values.global.jwtPolicy "third-party-jwt" }}
        - mountPath: /var/run/secrets/tokens
          name: istio-token
        {{- end }}
      ...
      volumes:
      {{- if eq .Values.global.jwtPolicy "third-party-jwt" }}
      - name: istio-token
        projected:
          sources:
          - serviceAccountToken:
              path: istio-token
              expirationSeconds: 43200
              audience: {{ .Values.global.sds.token.aud }}
      {{- end }}
```


而first-party-jwt是指kubernetes，`K8sSAJwtFileName`指定的路径是Kubernetes ServiceAccount自动挂载点，这个token的内容解析出来后，中间部分的内容如下(Istiod pod)：

```
{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "istio-system",
  "kubernetes.io/serviceaccount/secret.name": "istiod-service-account-token-97p6c",
  "kubernetes.io/serviceaccount/service-account.name": "istiod-service-account",
  "kubernetes.io/serviceaccount/service-account.uid": "effcaa6c-0595-4320-9897-e9f9bb9a411d",
  "sub": "system:serviceaccount:istio-system:istiod-service-account"
}
```

下面是客户端pod对应路径下jwt解析出来的内容

```
{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "foo",
  "kubernetes.io/serviceaccount/secret.name": "httpbin-token-c4mdk",
  "kubernetes.io/serviceaccount/service-account.name": "httpbin",
  "kubernetes.io/serviceaccount/service-account.uid": "22ef4914-614d-4d04-aa3a-7cd0f3ce3a78",
  "sub": "system:serviceaccount:foo:httpbin"
}
```

服务器端证书有两种类型：

	KubernetesCAProvider = "kubernetes"
	IstiodCAProvider     = "istiod"

默认为istiod

	PilotCertProvider = env.RegisterStringVar("PILOT_CERT_PROVIDER", "istiod",
		"the provider of Pilot DNS certificate.")

相关的ServiceAccount

- Istiod

  ```
  serviceAccount: istiod-service-account
  serviceAccountName: istiod-service-account
  ```



### createCA() ###

```
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

整体逻辑如下，根据./etc/cacerts/ca-key.pem是否存在，决定是否采用自签名证书还是已存在的证书，这两中情况最终都会生成一个IstioCAOptions对象，然后用它创建IstioCA，最后运行IstioCA.Run()

后两步其实都非常简单，代码如下

```
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

```
func (ca *IstioCA) Run(stopChan chan struct{}) {
	if ca.rootCertRotator != nil {
		// Start root cert rotator in a separate goroutine.
		go ca.rootCertRotator.Run(stopChan)
	}
}
```

可以看出如果是自签名证书，则会创建IstioCA.rootCertRotator对象，然后在IstioCA.Run()中将其启动，关于自签名证书的轮换我们后续单独进行分析，这里不再展开。

现在回头来看，ca服务的创建过程中比较复杂的逻辑在于如何创建IstioCAOptions对象，下面分别来进行分析。

#### 自签名证书 ####

如果./etc/cacerts/ca-key.pem不存在，则创建自签名证书。会调用NewSelfSignedIstioCAOptions()来实现

```
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

这里的整体逻辑是根据istio-ca-secret这个secret是否存在，决定是新建证书还是使用这个secret中的证书，等所有证书就绪后，会将证书绑定到一起形成IstioCAOptions.KeyCertBundle对象。然后会用根证书更新configmap，最后返回一个IstioCAOptions对象。

- istio-ca-secret不存在的情况

  首次运行时，这个secret是不存在的

  ```
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

- istio-ca-secret存在的情况

  ```
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

#### 使用用户指定的证书 ####

./etc/cacerts/ca-key.pem        ca私钥
./etc/cacerts/ca-cert.pem       ca证书
./etc/cacerts/ca-chain.pem      ca证书链
./etc/cacerts/root-cert.pem     根证书

实现的代码位于NewPluggedCertIstioCAOptions()

```
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

```
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

```
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

### initPublickKey() ###

ca证书路径Server.caBundlePath(string)的设置
第一种情况，如果是kubernetes，则会设置为`./var/run/secrets/kubernetes.io/serviceaccount/ca.crt`
第二种情况，如果是istiod，则会从.`/etc/cacerts`下读取，具体还分几种情况
    如果./etc/cacerts/ca-key.pem存在，则会设置为./etc/cacerts/cert-chain.pem
    否则使用./etc/cacerts/self-signed-root.pem自签名证书
第三种情况，不是kubernetes也不是istio，则会设置为`PILOT_CERT_PROVIDER`指定的目录中的cert-chain.pem

```
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

		if s.kubeClient != nil {
			fetchData := func() map[string]string {
				return map[string]string{
					constants.CACertNamespaceConfigMapDataName: string(s.ca.GetCAKeyCertBundle().GetRootCertPem()),
				}
			}
			s.addTerminatingStartFunc(func(stop <-chan struct{}) error {
				leaderelection.
					NewLeaderElection(args.Namespace, args.PodName, leaderelection.NamespaceController, s.kubeClient).
					AddRunFunction(func(stop <-chan struct{}) {
						log.Infof("Starting namespace controller")
						nc := kubecontroller.NewNamespaceController(fetchData, args.Config.ControllerOptions, s.kubeClient)
						nc.Run(stop)
					}).
					Run(stop)
				return nil
			})
		}
	}
```

### 自动生成证书 ###

如果没有手动指定，则会自动创建证书，位于

```
	// LocalCertDir replaces the "cert-chain", "signing-cert" and "signing-key" flags in citadel - Istio installer is
	// requires a secret named "cacerts" with specific files inside.
	LocalCertDir = env.RegisterStringVar("ROOT_CA_DIR", "./etc/cacerts",
		"Location of a local or mounted CA root")
```

"ca-key.pem"
"root-cert.pem"

自动生成证书的过程

- 载入kubernetes secret，位于istio-system namespace中

  ```
      // CASecret stores the key/cert of self-signed CA for persistency purpose.
      CASecret = "istio-ca-secret"
  ```

- 生成私钥和公钥
- 生成根证书，根证书中包含了刚生成的公钥，如果用户有指定根证书的话也会一并包含进去
- 把公钥、私钥和根证书打包到一起生成一个KeyCertBundle对象
- 将这些一起写回刚才的kubernetes secret
- 创建或者更新istio-system中的configmap

  ```
      IstioSecurityConfigMapName = "istio-security"
  ```

  内容是"caTLSRootCert:根证书"

  ```
      CATLSRootCertName          = "caTLSRootCert"
  ```

- 启动一个轮询，时间到了之后会更新根证书`istio-ca-secret`，代码位于`checkAndRotateRootCertForSigningCertCitadel()`

# 手动插入外部证书 #

## 旧的方式 ##

https://istio.io/latest/docs/tasks/security/cert-management/plugin-ca-cert/

ca-cert.pem     ca证书
ca-key.pem      ca私钥
cert-chain.pem  可能与ca-cert.pem相同
root-cert.pem   根证书

ca证书是由根证书签署的

```
$ kubectl create namespace istio-system
$ kubectl create secret generic cacerts -n istio-system --from-file=samples/certs/ca-cert.pem \
    --from-file=samples/certs/ca-key.pem --from-file=samples/certs/root-cert.pem \
    --from-file=samples/certs/cert-chain.pem
```

```
          - name: cacerts
            mountPath: /etc/cacerts
            readOnly: true
            ...
      volumes:
      ...
      # Optional: user-generated root
      - name: cacerts
        secret:
          secretName: cacerts
          optional: true
```

但是这种方式在代码注释里被称为是过时的，也就是为了向前兼容才保留这种方式，注释位于`pilot/pkg/bootstrap/istio_ca.go`中

```
// Based on istio_ca main - removing creation of Secrets with private keys in all namespaces and install complexity.
//
// For backward compat, will preserve support for the "cacerts" Secret used for self-signed certificates.
// It is mounted in the same location, and if found will be used - creating the secret is sufficient, no need for
// extra options.
//
// In old installer, the LocalCertDir is hardcoded to /etc/cacerts and mounted from "cacerts" secret.
//
// Support for signing other root CA has been removed - too dangerous, no clear use case.
//
// Default config, for backward compat with Citadel:
// - if "cacerts" secret exists in istio-system, will be mounted. It may contain an optional "root-cert.pem",
// with additional roots and optional {ca-key, ca-cert, cert-chain}.pem user-provided root CA.
// - if user-provided root CA is not found, the Secret "istio-ca-secret" is used, with ca-cert.pem and ca-key.pem files.
// - if neither is found, istio-ca-secret will be created.
//
// - a config map "istio-security" with a "caTLSRootCert" file will be used for root cert, and created if needed.
//   The config map was used by node agent - no longer possible to use in sds-agent, but we still save it for
//   backward compat. Will be removed with the node-agent. sds-agent is calling NewCitadelClient directly, using
//   K8S root.
```

## 新的方式 ##

```
	// Use TLS certificates if provided.
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.TLSOptions.CaCertFile, "caCertFile", "",
		"File containing the x509 Server CA Certificate")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.TLSOptions.CertFile, "tlsCertFile", "",
		"File containing the x509 Server Certificate")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.TLSOptions.KeyFile, "tlsKeyFile", "",
		"File containing the x509 private key matching --tlsCertFile")
```

这些证书同时用于Istiod的GRPC服务和DNS服务，同时，如果指定了根证书，也会禁用Istiod内部的ca服务。


# Istiod服务本身的证书 #
# Istiod的DNS证书 #

initDNSCerts()

包含三种情况：
一、kubernetes
二、istiod

./etc/cacerts/ca-key.pem ca私钥

根据用户是否指定这个ca私钥来确定是否使用自签名证书
如果是的话，会创建以下文件

	dnsCertDir  = "./var/run/secrets/istio-dns"
	dnsKeyFile  = "./" + filepath.Join(dnsCertDir, "key.pem")
	dnsCertFile = "./" + filepath.Join(dnsCertDir, "cert-chain.pem")

以及创建dnsCertDir+"self-signed-root.pem"作为内部自签名根证书，并将caBundlePath设置为这个证书的路径

三、其它

# old #

kubectl get secret $(kubectl get sa istiod-service-account  -n istio-system -o jsonpath='{.secrets[0].name}') -n istio-system -o jsonpath='{.data.token}' | base64 --decode

https://cloud.google.com/solutions/building-a-multi-cluster-service-mesh-on-gke-using-replicated-control-plane-architecture?hl=zh-cn#configuring_certificates_on_both_clusters

# 概述 #

ProxyConfig.DiscoveryAddress    "istiod.istio-system.svc:15012"
pilotCertProvider       "istiod"
outputKeyCertToDir      ""
ISTIO_META_CLUSTER_ID   "Kubernetes"

a.SDSAddress:  "unix:./etc/istio/proxy/SDS"
a.CAEndpoint(CA_ADDR): "istiod.istio-system.svc:15012"
a.RequireCerts: true

## 使用ServiceAccount作为证书 ##

```
  # Use the user-specified, secret volume mounted key and certs for Pilot and workloads.
  mountMtlsCerts: false
```

```
        {{- if .Values.global.mountMtlsCerts }}
        # Use the key and cert mounted to /etc/certs/ for the in-cluster mTLS communications.
        - mountPath: /etc/certs/
          name: istio-certs
          readOnly: true
        {{- end }}

      volumes:
      ...
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

存放路径`/etc/certs`

用户请求根证书时缓存的路径
RootCertReqResourceName  = "ROOTCA"
DefaultRootCertFilePath  = "./etc/certs/root-cert.pem"

用户请求普通证书时缓存的路径
defaultCertChainFilePath = "./etc/certs/cert-chain.pem"
defaultKeyFilePath       = "./etc/certs/key.pem"

        {{- if .Values.global.mountMtlsCerts }}
        # Use the key and cert mounted to /etc/certs/ for the in-cluster mTLS communications.
        - mountPath: /etc/certs/
          name: istio-certs
          readOnly: true
        {{- end }}
        - name: istio-podinfo
          mountPath: /etc/istio/pod
         {{- if and (eq .Values.global.proxy.tracer "lightstep") .ProxyConfig.GetTracing.GetTlsSettings }}
        - mountPath: {{ directory .ProxyConfig.GetTracing.GetTlsSettings.GetCaCertificates }}
          name: lightstep-certs
          readOnly: true
        {{- end }}

# chiron #

https://istio.io/latest/zh/docs/tasks/security/dns-cert/

	// Default CA certificate path
	// Currently, custom CA path is not supported; no API to get custom CA cert yet.
	defaultCACertPath = "./var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
