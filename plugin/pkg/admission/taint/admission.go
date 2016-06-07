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

package taint

import (
	"errors"
	"fmt"
	"io"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/apis/rbac/validation"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/unversioned"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/tpm"

	apierrors "k8s.io/kubernetes/pkg/api/errors"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
)

/*
This admission controller does two things:

1) Automatically taint new nodes in order to ensure that jobs will not be
scheduled on them

2) Blocks writes to certain items of node metadata, configmaps and
third-party objectsunless the user has the tpmadmin flag

(2) is a hack due to the lack of sufficiently fine-grained access control. Node
taints are simply an annotation, and annotations are a free-form map. In order
to use generic functionality, it will be necessary to be able to restrict
access to specific annotations. It will also be necessary to be able to provide
ACLs for third party objects.
*/

const TaintConfig string = "taint.coreos.com"

func newRbacClient(client clientset.Interface) validation.AuthorizationRuleResolver {
	c := &rbacClient{client.Rbac()}
	return validation.NewDefaultRuleResolver(c, c, c, c)
}

type rbacClient struct {
	client unversioned.RbacInterface
}

func (c *rbacClient) GetClusterRole(ctx api.Context, id string) (*rbac.ClusterRole, error) {
	return c.client.ClusterRoles().Get(id)
}

func (c *rbacClient) ListClusterRoleBindings(ctx api.Context, options *api.ListOptions) (*rbac.ClusterRoleBindingList, error) {
	return c.client.ClusterRoleBindings().List(*options)
}

func (c *rbacClient) GetRole(ctx api.Context, id string) (*rbac.Role, error) {
	ns, ok := api.NamespaceFrom(ctx)
	if !ok {
		return nil, errors.New("no namespace found")
	}
	role, err := c.client.Roles(ns).Get(id)
	if err != nil {
		return nil, fmt.Errorf("get role: %v", err)
	}
	return role, nil
}

func (c *rbacClient) ListRoleBindings(ctx api.Context, options *api.ListOptions) (*rbac.RoleBindingList, error) {
	ns, ok := api.NamespaceFrom(ctx)
	if !ok {
		return nil, errors.New("no namespace found")
	}
	roleBindings, err := c.client.RoleBindings(ns).List(*options)
	if err != nil {
		return nil, fmt.Errorf("list role bindings: %v", err)
	}
	return roleBindings, nil
}

func init() {
	admission.RegisterPlugin("TaintAdmit", func(client clientset.Interface, config io.Reader) (admission.Interface, error) {
		return NewTaintAdmit(client, config), nil
	})
}

// TaintAdmit is an implementation of admission.Interface which taints nodes at creation time
type taintAdmit struct {
	client clientset.Interface
}

func toleratesUntrusted(pod *api.Pod) (bool, error) {
	tolerations, err := api.GetTolerationsFromPodAnnotations(pod.Annotations)
	if err != nil {
		return false, err
	}
	for _, toleration := range tolerations {
		if toleration.Key == tpm.TaintKey {
			return true, nil
		}
	}
	return false, nil
}

func (t *taintAdmit) Admit(a admission.Attributes) (err error) {
	kind := a.GetKind().GroupKind()

	user := a.GetUserInfo()
	// Allow access over the insecure socket to do anything
	if user == nil {
		return nil
	}

	if kind != api.Kind("Node") && kind != api.Kind("ConfigMap") && kind != api.Kind("Pod") && kind != api.Kind("Policy") && kind != api.Kind("Tpm") {
		return nil
	}

	configmap, err := t.client.Core().ConfigMaps(api.NamespaceDefault).Get(TaintConfig)
	if err != nil {
		return apierrors.NewBadRequest("Unable to obtain taint ConfigMap")
	}

	if configmap == nil || configmap.Data["taint"] != "true" {
		return nil
	}

	namespace := a.GetNamespace()
	tpmAdmin := false

	// Check whether the user has a role that provides the tpmadmin attribute
	rbac := newRbacClient(t.client)
	ctx := api.WithUser(api.WithNamespace(api.NewContext(), api.NamespaceSystem), user)
	rules, err := rbac.GetEffectivePolicyRules(ctx)
	if err == nil {
		for _, rule := range rules {
			restrictions, ok := rule.AttributeRestrictions.(*runtime.Unknown)
			if ok && string(restrictions.Raw) == "\"tpmadmin\"" {
				tpmAdmin = true
				break
			}
		}
	} else {
		glog.Errorf("Unable to obtain user rules for taintAdmissionController: %v", err)
	}

	// Allow admin users to do whatever they want
	if tpmAdmin == true {
		return nil
	}

	// Unprivileged users aren't allowed to perform actions that would alter the trust state
	switch kind {
	case api.Kind("Tpm"):
		return apierrors.NewBadRequest("Unauthorised attempt to modify TPM object")
	case api.Kind("Policy"):
		return apierrors.NewBadRequest("Unauthorised attempt to modify TPM policy object")
	case api.Kind("ConfigMap"):
		name := a.GetName()
		// A create operation may not provide a name directly, so pull it out of the object if we didn't get one
		if name == "" {
			configmap, ok := a.GetObject().(*api.ConfigMap)
			if !ok {
				return apierrors.NewBadRequest("Resource was marked with kind ConfigMap but couldn't be type converted")
			}
			name = configmap.Name
		}
		// Only permit TPM admins to modify these, otherwise nodes can circumvent security policy
		if name == TaintConfig || name == tpm.TpmManagerConfig {
			return apierrors.NewBadRequest("Unauthorised attempt to modify taint configuration")
		}
		return nil
	case api.Kind("Node"):
		operation := a.GetOperation()
		if operation != admission.Create && operation != admission.Update {
			return nil
		}

		node, ok := a.GetObject().(*api.Node)
		if !ok {
			return apierrors.NewBadRequest("Resource was marked with kind Node but couldn't be type converted")
		}
		if operation == admission.Create {
			err := tpm.InvalidateNode(node)
			if err != nil {
				return fmt.Errorf("Unable to invalidate node: %v", err)
			}
			return nil
		}

		// If an external update tries to switch a node from untrusted to trusted, force it back to untrusted
		trusted, err := tpm.IsTrusted(node)
		if err != nil {
			return fmt.Errorf("Unable to identify node trusted status: %v", err)
		}
		if trusted == true {
			oldNode, err := t.client.Core().Nodes().Get(node.Name)
			if err != nil {
				return fmt.Errorf("Attempting to update a node that doesn't exist? %v", err)
			}
			oldTrusted, err := tpm.IsTrusted(oldNode)
			if err != nil || oldTrusted == false {
				glog.Errorf("User %v attempted to flag untrusted node %v as trusted", user, node.Name)
				return apierrors.NewBadRequest("Attempted to flag untrusted node as trusted")
			}
		}
		return nil
	case api.Kind("Pod"):
		operation := a.GetOperation()
		if operation != admission.Update {
			return nil
		}
		pod, ok := a.GetObject().(*api.Pod)
		if !ok {
			return apierrors.NewBadRequest("Resource was marked with kind Pod but couldn't be type converted")
		}
		tolerates, err := toleratesUntrusted(pod)
		if err != nil {
			return fmt.Errorf("Unable to identify pod toleration status: %v", err)
		}
		if tolerates == true {
			oldPod, err := t.client.Core().Pods(namespace).Get(pod.Name)
			if err != nil {
				return fmt.Errorf("Attempting to update a pod that doesn't exist? %v", err)
			}
			oldTolerates, err := toleratesUntrusted(oldPod)
			if err != nil || oldTolerates == false {
				glog.Errorf("User %v attempted to flag pod %v as tolerating untrusted nodes", user, pod.Name)
				return apierrors.NewBadRequest("Invalid attempt to declare that a pod tolerates untrusted nodes")
			}
		}
	}
	return nil
}

func (taintAdmit) Handles(operation admission.Operation) bool {
	return true
}

// NewTaintAdmit creates a new TaintAdmit handler
func NewTaintAdmit(c clientset.Interface, config io.Reader) admission.Interface {
	taintadmit := &taintAdmit{
		client: c,
	}
	return taintadmit
}
