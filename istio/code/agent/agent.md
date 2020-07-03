---
title: "第一章 Agent主要组件及启动流程"
linkTitle: "第一章 Agent主要组件"
weight: 1
date: 2017-01-04
description: >
---

{{< figure src="../agent_1.png" link="../agent_1.png" target="_blank" >}}

Pilot Agent主要作用是在内部启动一个envoy进程。

## 概述 ##

它包括几个部分

- agent

  即Pilot Agent的主进程

  ``` golang
  type agent struct {
      proxy Proxy
      activeEpochs map[int]chan error
      currentEpoch int
      statusCh chan exitStatus
      ...
  }
  ```

  agent会在内部跟踪启动的envoy进程，它包含了一个递增的全局变量`currentEpoch`用来记录最近启动/重启的envoy进程，每次重启的时候这个值都会加1。

  另外，在Pilot Agent中可能存在不止一个envoy进程，这种情况下就需要对它们进行记录和跟踪，成员变量`activeEpochs`就是用来做这个事的，它是dict类型，key就是每个envoy进程对应的`currentEpoch`的值，对应的value是一个channel，在需要退出的时候，agent通过这个channel来给对应的envoy发送信号。当`activeEpochs`为空的时候，整个Pilot Agent就会退出。

  在agent中还有一个名为`statusCh`的channel类型的成员，当envoy重启或者结束时，会通过这个channel向agent汇报结束状态。

  其中的proxy见下文描述。

- proxy

  是对envoy进程的封装，是它负责把envoy进程运行起来，这个对象作为一个成员被包含在agent里。

- watcher

  一个监视器，它会watch Pilot Agent pod挂载的证书文件，如果证书文件发生变化，它就会调用预先注册的`agent.Restart()`这个回调函数来重启envoy进程。

- Secret discovery service (SDS) Agent

  一个SDS服务，负责与Istiod(Pilot Discovery)以及Envoy进程进行交换签名等操作。会在后面单独一个部分进行分析。

## 启动过程 ##

入口在`pilot/cmd/pilot-agent/main.go`中，

``` golang
	proxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "Envoy proxy agent",
		RunE: func(c *cobra.Command, args []string) error {
			cmd.PrintFlags(c.Flags())
            ...
```

1. 首先，会初始化一些变量，载入默认配置等等。

2. 接着会创建SDS Agent对象，并将其Run起来

   ``` golang
			sa := istio_agent.NewSDSAgent(proxyConfig.DiscoveryAddress, proxyConfig.ControlPlaneAuthPolicy == meshconfig.AuthenticationPolicy_MUTUAL_TLS,
            ...
			_, err = sa.Start(role.Type == model.SidecarProxy, podNamespaceVar.Get())
			if err != nil {
				log.Fatala("Failed to start in-process SDS", err)
			}
   ```

3. 然后根据配置，如果有证书文件需要watch，先等待他们ready

    ``` golang
			// dedupe cert paths so we don't set up 2 watchers for the same file
			tlsCerts := dedupeStrings(getTLSCerts(proxyConfig))

			// Since Envoy needs the file-mounted certs for mTLS, we wait for them to become available
			// before starting it.
			if len(tlsCerts) > 0 {
				log.Infof("Monitored certs: %#v", tlsCerts)
				for _, cert := range tlsCerts {
					waitForFile(cert, 2*time.Minute)
				}
			}
   ```

4. 创建proxy对象和agent对象

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

			agent := envoy.NewAgent(envoyProxy, features.TerminationDrainDuration())
   ```

5. 创建watcher并Run，这里将agent.Restart作为回调函数注册到了watcher对象里。

   ``` golang
			// Watcher is also kicking envoy start.
			watcher := envoy.NewWatcher(tlsCerts, agent.Restart)
			go watcher.Run(ctx)
   ```

6. 最后，启动agent。

   ``` golang
			return agent.Run(ctx)
   ```

## 深入分析 ##

先来看agent.Run()

``` golang
func (a *agent) Run(ctx context.Context) error {
	log.Info("Starting proxy agent")
	for {
		select {
		case status := <-a.statusCh:
			a.mutex.Lock()
			if status.err != nil {
                ...
				log.Errorf("Epoch %d exited with error: %v", status.epoch, status.err)
			} else {
				log.Infof("Epoch %d exited normally", status.epoch)
			}

			delete(a.activeEpochs, status.epoch)

			active := len(a.activeEpochs)
			a.mutex.Unlock()

			if active == 0 {
				log.Infof("No more active epochs, terminating")
				return nil
			}

			log.Infof("%d active epochs running", active)

		case <-ctx.Done():
			a.terminate()
			log.Info("Agent has successfully terminated")
			return nil
		}
	}
}
```

agent运行之后会监听agent.statusCh，在之前提到过，每当envoy进程退出时，会使用这个channel向agent汇报退出状态，这里可以看到当envoy退出时agent会删除agent.activeEpochs这个dict中的记录，然后重新检测这个dict，如果为空，则表明所有的envoy进程都已经退出，结束整个程序。

可以看出envoy进程并不是由agent.Run()启动的，它的启动实际上是由wather来触发的。下面是watcher的结构

``` golang
type watcher struct {
	certs   []string
	updates func(interface{})
}
```

watcher的结构非常简单，包含证书名称的一个数组和一个回调函数，下面详细看watcher对象的创建和运行过程。

``` golang
			// Watcher is also kicking envoy start.
			watcher := envoy.NewWatcher(tlsCerts, agent.Restart)
			go watcher.Run(ctx)
```

在创建时将`agent.Restart`作为回调函数存储在`updates`字段中。

``` golang
func (w *watcher) Run(ctx context.Context) {
	// kick start the proxy with partial state (in case there are no notifications coming)
	w.SendConfig()

	// monitor certificates
	go watchCerts(ctx, w.certs, watchFileEvents, defaultMinDelay, w.SendConfig)

	<-ctx.Done()
	log.Info("Watcher has successfully terminated")
}
```

watcher运行后会首先调用一次`SendConfig()`，然后又把`SendConfig()`作为回调函数执行了一个goroutine，即`watchFileEvents()`，这个函数的作用就是watch证书文件，监测到有变化的时候再次调用`SendConfig()`(注意不是立即调用，而是有一个计时器，每次调用间隔不小于`defaultMinDelay`)。

下面看`SendConfig()`

``` golang
func (w *watcher) SendConfig() {
	h := sha256.New()
	generateCertHash(h, w.certs)
	w.updates(h.Sum(nil))
}
```

它会计算证书的sha256的值，然后将其作为参数调用`watcher.updates()`，也就是调用前文提到的已经注册的回调函数`agent.Restart()`

``` golang
func (a *agent) Restart(config interface{}) {
	// Only allow one restart to execute at a time.
	a.restartMutex.Lock()
	defer a.restartMutex.Unlock()

	// Protect access to internal state.
	a.mutex.Lock()

	if reflect.DeepEqual(a.currentConfig, config) {
		// Same configuration - nothing to do.
		a.mutex.Unlock()
		return
	}

	hasActiveEpoch := len(a.activeEpochs) > 0
	activeEpoch := a.currentEpoch

	// Increment the latest running epoch
	epoch := a.currentEpoch + 1
	log.Infof("Received new config, creating new Envoy epoch %d", epoch)

	a.currentEpoch = epoch
	a.currentConfig = config

	// Add the new epoch to the map.
	abortCh := make(chan error, 1)
	a.activeEpochs[a.currentEpoch] = abortCh

	// Unlock before the wait to avoid delaying envoy exit logic.
	a.mutex.Unlock()

	// Wait for previous epoch to go live (if one exists) before performing a hot restart.
	if hasActiveEpoch {
		a.waitUntilLive(activeEpoch)
	}

	go a.runWait(config, epoch, abortCh)
}
```

`agent.Restart()`为启动envoy作一些准备工作，它会将watcher传回的证书文件的sha256的值存储到agent.currentConfig中，然后将epoch+1，将新的epoch和对应的channel注册到agent.activeEpochs中，然后再使用这两个值加上证书的sha256的值，这三个作为参数调用agent.runWait()来启动envoy。

``` golang
// runWait runs the start-up command as a go routine and waits for it to finish
func (a *agent) runWait(config interface{}, epoch int, abortCh <-chan error) {
	log.Infof("Epoch %d starting", epoch)
	err := a.proxy.Run(config, epoch, abortCh)
	a.proxy.Cleanup(epoch)
	a.statusCh <- exitStatus{epoch: epoch, err: err}
}
```

`runWait()`内部会将这几个参数再次传递给`agent.Proxy.Run()`，就像本文开始所讲的，实际上envoy是由agent.Proxy来真正启动的。

envoy运行结束后会通过agent.statusCh将退出信息传回proxy.Run()，后者会清除旧的envoy进程记录。
