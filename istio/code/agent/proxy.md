---
title: "第二章 Envoy启动过程分析"
linkTitle: "第二章 Envoy启动过程"
weight: 2
date: 2017-01-04
description: >
---

TODO

``` golang
			envoyProxy := envoy.NewProxy(envoy.ProxyConfig{
				Config:              proxyConfig,
				Node:                role.ServiceNode(),
				LogLevel:            proxyLogLevel,
				ComponentLogLevel:   proxyComponentLogLevel,
				PilotSubjectAltName: pilotSAN,
				MixerSubjectAltName: mixerSAN,
				NodeIPs:             role.IPAddresses,
				PodName:             podName,
				PodNamespace:        podNamespace,
				PodIP:               podIP,
				STSPort:             stsPort,
				ControlPlaneAuth:    proxyConfig.ControlPlaneAuthPolicy == meshconfig.AuthenticationPolicy_MUTUAL_TLS,
				DisableReportCalls:  disableInternalTelemetry,
				OutlierLogPath:      outlierLogPath,
				PilotCertProvider:   pilotCertProvider,
				ProvCert:            citadel.ProvCert,
			})
```


``` golang
// NewProxy creates an instance of the proxy control commands
func NewProxy(cfg ProxyConfig) Proxy {
	// inject tracing flag for higher levels
	var args []string
	if cfg.LogLevel != "" {
		args = append(args, "-l", cfg.LogLevel)
	}
	if cfg.ComponentLogLevel != "" {
		args = append(args, "--component-log-level", cfg.ComponentLogLevel)
	}

	return &envoy{
		ProxyConfig: cfg,
		extraArgs:   args,
	}
}
```

``` golang
func (e *envoy) Run(config interface{}, epoch int, abort <-chan error) error {
	var fname string
	// Note: the cert checking still works, the generated file is updated if certs are changed.
	// We just don't save the generated file, but use a custom one instead. Pilot will keep
	// monitoring the certs and restart if the content of the certs changes.
	if len(e.Config.CustomConfigFile) > 0 {
		// there is a custom configuration. Don't write our own config - but keep watching the certs.
		fname = e.Config.CustomConfigFile
	} else {
		out, err := bootstrap.New(bootstrap.Config{
			Node:                e.Node,
			Proxy:               &e.Config,
			PilotSubjectAltName: e.PilotSubjectAltName,
			MixerSubjectAltName: e.MixerSubjectAltName,
			LocalEnv:            os.Environ(),
			NodeIPs:             e.NodeIPs,
			PodName:             e.PodName,
			PodNamespace:        e.PodNamespace,
			PodIP:               e.PodIP,
			STSPort:             e.STSPort,
			ControlPlaneAuth:    e.ControlPlaneAuth,
			DisableReportCalls:  e.DisableReportCalls,
			OutlierLogPath:      e.OutlierLogPath,
			PilotCertProvider:   e.PilotCertProvider,
			ProvCert:            e.ProvCert,
		}).CreateFileForEpoch(epoch)
		if err != nil {
			log.Errora("Failed to generate bootstrap config: ", err)
			os.Exit(1) // Prevent infinite loop attempting to write the file, let k8s/systemd report
		}
		fname = out
	}

	// spin up a new Envoy process
	args := e.args(fname, epoch, istioBootstrapOverrideVar.Get())
	log.Infof("Envoy command: %v", args)

	/* #nosec */
	cmd := exec.Command(e.Config.BinaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-abort:
		log.Warnf("Aborting epoch %d", epoch)
		if errKill := cmd.Process.Kill(); errKill != nil {
			log.Warnf("killing epoch %d caused an error %v", epoch, errKill)
		}
		return err
	case err := <-done:
		return err
	}
}
```

envoy启动参数

``` golang
2020-05-25T07:44:13.334932Z	info	Envoy command: [-c etc/istio/proxy/envoy-rev0.json --restart-epoch 0 --drain-time-s 45 --parent-shutdown-time-s 60 --service-cluster productpage.default --service-node sidecar~10.244.0.16~productpage-v1-85b9bf9cd7-kpr5h.default~default.svc.cluster.local --max-obj-name-len 189 --local-address-ip-version v4 --log-format %Y-%m-%dT%T.%fZ	%l	envoy %n	%v -l warning --component-log-level misc:error --concurrency 2]
```

所使用的的image             `docker.io/istio/proxyv2:1.6.0`

对应的Dockerfile           `pilot/docker/Dockerfile.proxyv2`

envoy配置文件所对应的模板文件   'tools/packaging/common/envoy_bootstrap_v2.json'
