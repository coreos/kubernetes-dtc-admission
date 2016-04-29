/*
Copyright 2014 The Kubernetes Authors All rights reserved.
Copyright 2015 CoreOS, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/componentconfig"
	"k8s.io/kubernetes/pkg/client/cache"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/client/leaderelection"
	"k8s.io/kubernetes/pkg/client/record"
	"k8s.io/kubernetes/pkg/client/restclient"
	unversionedclient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/flag"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/kubernetes/pkg/util/tpm"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"
)

const (
	LogState       string = "alpha.tpm.coreos.com/logstate"
	UntrustedSince string = "alpha.tpm.coreos.com/untrustedsince"
	TrustedSince   string = "alpha.tpm.coreos.com/trustedsince"
	ValidationTime string = "alpha.tpm.coreos.com/validationtime"
	TpmPort        string = "23179"
)

func trustNode(node *api.Node) error {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	newTaints := []api.Taint{}
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	if err != nil {
		return fmt.Errorf("Unable to obtain node annotations: %v", err)
	}
	for _, taint := range taints {
		if taint.Key == tpm.TaintKey {
			continue
		}
		newTaints = append(newTaints, taint)
	}
	jsonContent, err := json.Marshal(newTaints)
	if err == nil {
		node.Annotations[api.TaintsAnnotationKey] = string(jsonContent)
	}
	return err
}

func loadPolicy() (err error) {
	manager.pcrConfigs = make([]map[string]tpm.PCRConfig, 0)

	if manager.pcrConfig != "" {
		pcrdata := make(map[string]tpm.PCRConfig)
		pcrConfig, err := ioutil.ReadFile(manager.pcrConfig)
		if err != nil {
			return fmt.Errorf("Unable to read valid PCR configuration %s: %v", manager.pcrConfig, err)
		}
		err = json.Unmarshal(pcrConfig, &pcrdata)
		if err != nil {
			return fmt.Errorf("Unable to parse valid PCR configuration %s: %v", manager.pcrConfig, err)
		}
		for pcrKey, pcrVal := range pcrdata {
			pcrtmp := pcrVal
			pcrtmp.Source = manager.pcrConfig
			pcrdata[pcrKey] = pcrtmp
		}
		manager.pcrConfigs = append(manager.pcrConfigs, pcrdata)
	} else if manager.pcrConfigDir != "" {
		err = filepath.Walk(manager.pcrConfigDir, func(path string, f os.FileInfo, err error) error {
			if err != nil {
				glog.Errorf("Unable to walk %s: %v", path, err)
				return nil
			}
			if f.IsDir() {
				return nil
			}
			pcrConfig, err := ioutil.ReadFile(path)
			if err != nil {
				return fmt.Errorf("Unable to read PCR configuration %s: %v", path, err)
			}
			pcrdata := make(map[string]tpm.PCRConfig)
			err = json.Unmarshal(pcrConfig, &pcrdata)
			if err != nil {
				return fmt.Errorf("Unable to parse valid PCR configuration %s: %v", path, err)
			}
			for pcr, _ := range pcrdata {
				pcrtmp := pcrdata[pcr]
				pcrtmp.Source = path
				pcrdata[pcr] = pcrtmp
			}
			manager.pcrConfigs = append(manager.pcrConfigs, pcrdata)
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		manager.pcrConfigs, err = manager.tpmhandler.GetPolicies()
		if err != nil {
			return fmt.Errorf("Unable to obtain PCR configuration: %v", err)
		}
	}
	return nil
}

func updateLogStateAnnotations(node *api.Node, log string) {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	node.ObjectMeta.Annotations[LogState] = log
}

func verifyNode(node *api.Node) error {
	address, err := nodeutil.GetNodeHostIP(node)
	if err != nil {
		return err
	}
	host := fmt.Sprintf("%s:%d", address.String(), TpmPort)
	tpmdata, err := manager.tpmhandler.Get(host, manager.allowUnknown)
	if err != nil {
		err = tpm.InvalidateNode(node)
		if err != nil {
			return fmt.Errorf("Failed to invalidate node: %v", err)
		}
		return fmt.Errorf("Invalidating Node: Unable to obtain TPM data for node %s: %v", node.Name, err)
	}
	quote, log, err := tpm.Quote(tpmdata)
	if err != nil {
		err = tpm.InvalidateNode(node)
		if err != nil {
			return fmt.Errorf("Failed to invalidate node: %v", err)
		}
		return fmt.Errorf("Invalidating Node: Unable to obtain TPM quote for node %s: %v", node.Name, err)
	}

	err = tpm.ValidateLog(log, quote)
	if err != nil {
		err = tpm.InvalidateNode(node)
		if err != nil {
			return fmt.Errorf("Failed to invalidate node: %v", err)
		}
		return fmt.Errorf("Invalidating Node: TPM event log does not match quote for node %s", node.Name)
	}

	// Don't handle this error immediately - we want to update the annotations even if validation failed
	logstate, err := tpm.ValidatePCRs(log, quote, manager.pcrConfigs)
	jsonlog, jsonerr := json.Marshal(logstate)

	if jsonerr == nil {
		updateLogStateAnnotations(node, string(jsonlog))
	} else {
		glog.Errorf("Failed to serialise new log state: %v", jsonerr)
	}

	if err != nil {
		err = tpm.InvalidateNode(node)
		if err != nil {
			return fmt.Errorf("Failed to invalidate node: %v", err)
		}
		return fmt.Errorf("Invalidating Node: Unable to validate quote for node %s", node.Name)
	}

	// If we've got this far then the node is trustworthy
	err = trustNode(node)
	if err != nil {
		return fmt.Errorf("Failed to mark node as trustworthy: %v", err)
	}
	return nil
}

func verifyAndUpdate(node *api.Node) {
	err := verifyNode(node)
	if err != nil {
		glog.Errorf("Failed to verify node %s: %v", node.Name, err)
	}

	// The state that the node will be updated to
	newstate, err := tpm.IsTrusted(node)
	if err != nil {
		glog.Errorf("Unable to obtain node state for %s: %v", node.Name, err)
		return
	}
	newnode, err := manager.clientset.Nodes().Get(node.Name)
	if err != nil {
		glog.Errorf("Unable to obtain node state for %s: %v", node.Name, err)
		return
	}
	if newnode.ObjectMeta.Annotations == nil {
		newnode.ObjectMeta.Annotations = make(map[string]string)
	}
	currenttime := time.Now().Unix()

	// If we're transitioning state, update the metadata
	state, err := tpm.IsTrusted(newnode)
	if err != nil {
		glog.Errorf("Unable to obtain node state for %s: %v", newnode.Name, err)
		return
	}
	if state != newstate {
		if newstate == false {
			newnode.ObjectMeta.Annotations[UntrustedSince] = strconv.FormatInt(currenttime, 10)
			newnode.ObjectMeta.Annotations[TrustedSince] = ""
		} else {
			newnode.ObjectMeta.Annotations[UntrustedSince] = ""
			newnode.ObjectMeta.Annotations[TrustedSince] = strconv.FormatInt(currenttime, 10)
		}
	}

	newnode.ObjectMeta.Annotations[ValidationTime] = strconv.FormatInt(currenttime, 10)

	// Ensure that the new node is tainted appropriately
	if newstate == true {
		err = trustNode(newnode)
	} else {
		err = tpm.InvalidateNode(newnode)
	}
	if err != nil {
		glog.Errorf("Failed to change node trust state for %s: %v", node.Name, err)
	}
	newnode.ObjectMeta.Annotations[LogState] = node.ObjectMeta.Annotations[LogState]
	_, err = manager.clientset.Nodes().Update(newnode)
	if err != nil {
		glog.Errorf("Unable to update node state for %s: %v", node.Name, err)
		return
	}
}

func verifyAllNodes() {
	nodes, err := manager.clientset.Nodes().List(api.ListOptions{})
	if err != nil {
		glog.Errorf("Unable to obtain list of nodes")
		return
	}
	for _, node := range nodes.Items {
		verifyAndUpdate(&node)
	}
}

func reverify() {
	for {
		select {
		case <-time.After(time.Duration(manager.recurring) * time.Second):
			verifyAllNodes()
		case <-manager.recurringChan:
		}
	}
}

type TPMManager struct {
	Master        string
	Kubeconfig    string
	tpmhandler    tpm.TPMHandler
	pcrConfig     string
	pcrConfigDir  string
	allowUnknown  bool
	recurring     int
	clientset     *clientset.Clientset
	policyTimer   *time.Timer
	leaderelect   componentconfig.LeaderElectionConfiguration
	recurringChan chan int
	pcrConfigs    []map[string]tpm.PCRConfig
}

var manager TPMManager

func addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&manager.Master, "master", manager.Master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&manager.Kubeconfig, "kubeconfig", manager.Kubeconfig, "Path to kubeconfig file with authorization and master location information.")
	fs.StringVar(&manager.pcrConfig, "pcrConfig", manager.pcrConfig, "Path to a single PCR config file")
	fs.StringVar(&manager.pcrConfigDir, "pcrConfigDir", manager.pcrConfigDir, "Path to a PCR config directory")
	fs.BoolVar(&manager.allowUnknown, "allowUnknown", false, "Allow unknown TPMs to join the cluster")
	fs.IntVar(&manager.recurring, "reverify", 0, "Periodocally reverify nodes after this many seconds")
}

func updateConfig(configmap *api.ConfigMap) {
	if configmap.Data["allowunknown"] != "" {
		allowUnknown, err := strconv.ParseBool(configmap.Data["allowunknown"])
		if err == nil {
			manager.allowUnknown = allowUnknown
		} else {
			glog.Errorf("Unable to parse allowunknown value: %s", allowUnknown)
		}
	}
	if configmap.Data["reverify"] != "" {
		reverify, err := strconv.Atoi(configmap.Data["reverify"])
		if err == nil {
			manager.recurring = reverify
			// Trigger the reverification logic. If it's already in the
			// middle of reverifying, drop the event - it'll handle it
			// at the end of reverification.
			select {
			case manager.recurringChan <- reverify:
			default:
			}
		} else {
			glog.Errorf("Unable to parse reverify value: %s", reverify)
		}
	}
}

func run(stop <-chan struct{}) {
	_, nodeController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return manager.clientset.Nodes().List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return manager.clientset.Nodes().Watch(options)
			},
		},
		&api.Node{},
		time.Second,
		framework.ResourceEventHandlerFuncs{
			AddFunc: nodeAddFn,
		},
	)

	_, configController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return manager.clientset.ConfigMaps(api.NamespaceSystem).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return manager.clientset.ConfigMaps(api.NamespaceSystem).Watch(options)
			},
		},
		&api.ConfigMap{},
		time.Second,
		framework.ResourceEventHandlerFuncs{
			AddFunc:    configAddFn,
			UpdateFunc: configUpdateFn,
		},
	)

	_, policyController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return manager.tpmhandler.PolicyClient.List(&options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return manager.tpmhandler.PolicyClient.Watch(&options)
			},
		},
		&runtime.Unstructured{},
		time.Second,
		framework.ResourceEventHandlerFuncs{
			AddFunc:    policyAddFn,
			UpdateFunc: policyUpdateFn,
			DeleteFunc: policyDeleteFn,
		},
	)
	err := loadPolicy()
	if err != nil {
		glog.Errorf("Unable to load PCR policy: %v", err)
		os.Exit(1)
	}
	go reverify()
	go nodeController.Run(wait.NeverStop)
	go configController.Run(wait.NeverStop)
	go policyController.Run(wait.NeverStop)
	select {}
}

func main() {
	var tpmhandler tpm.TPMHandler

	config, err := restclient.InClusterConfig()
	if err != nil {
		fmt.Printf("Unable to obtain client configuration: %v", err)
		os.Exit(1)
	}
	config.Host = "http://localhost:8080"
	client := clientset.NewForConfigOrDie(config)
	kubeClient, err := unversionedclient.New(config)
	if err != nil {
		fmt.Printf("Unable to create client: %v", err)
		os.Exit(1)
	}
	config.APIPath = "apis/coreos.com"
	err = tpmhandler.Setup(config)
	if err != nil {
		fmt.Printf("Unable to set up TPM handler: %v", err)
		os.Exit(1)
	}
	configmap, err := client.ConfigMaps(api.NamespaceSystem).Get(tpm.TpmManagerConfig)
	if err == nil && configmap != nil {
		updateConfig(configmap)
	}

	addFlags(pflag.CommandLine)
	leaderelection.BindFlags(&manager.leaderelect, pflag.CommandLine)
	flag.InitFlags()

	manager.clientset = client
	manager.tpmhandler = tpmhandler
	manager.recurringChan = make(chan int)

	if !manager.leaderelect.LeaderElect {
		run(wait.NeverStop)
	}

	id, err := os.Hostname()
	if err != nil {
		fmt.Printf("Unable to obtain hostname: %v", err)
		return
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(client.Events(""))
	recorder := eventBroadcaster.NewRecorder(api.EventSource{Component: "tpm-manager"})

	leaderelection.RunOrDie(leaderelection.LeaderElectionConfig{
		EndpointsMeta: api.ObjectMeta{
			Namespace: api.NamespaceSystem,
			Name:      "tpm-manager",
		},
		Client:        kubeClient,
		Identity:      id,
		EventRecorder: recorder,
		LeaseDuration: manager.leaderelect.LeaseDuration.Duration,
		RenewDeadline: manager.leaderelect.RenewDeadline.Duration,
		RetryPeriod:   manager.leaderelect.RetryPeriod.Duration,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				glog.Fatalf("leaderelection lost")
			},
		},
	})
}

func nodeAddFn(obj interface{}) {
	node, ok := obj.(*api.Node)
	if !ok {
		glog.Errorf("Node add got a non-Node")
		return
	}
	verifyAndUpdate(node)
}

func configAddFn(obj interface{}) {
	configmap, ok := obj.(*api.ConfigMap)
	if !ok {
		glog.Errorf("Config add got a non-ConfigMap")
		return
	}
	if configmap.Name != tpm.TpmManagerConfig {
		return
	}
	updateConfig(configmap)
}

func configUpdateFn(oldObj, newObj interface{}) {
	configAddFn(newObj)
}

func updatePolicy() {
	err := loadPolicy()
	if err != nil {
		glog.Errorf("Unable to parse updated policy: %v", err)
	} else {
		verifyAllNodes()
	}
}

func scheduleVerification() {
	if manager.policyTimer != nil {
		manager.policyTimer.Stop()
	}
	manager.policyTimer = time.AfterFunc(time.Second, updatePolicy)
}

func policyAddFn(obj interface{}) {
	scheduleVerification()
}

func policyUpdateFn(oldobj, newobj interface{}) {
	scheduleVerification()
}

func policyDeleteFn(obj interface{}) {
	scheduleVerification()
}
