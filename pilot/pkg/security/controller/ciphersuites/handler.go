package ciphersuites

import (
    "context"
    "fmt"
    "time"
	"bytes"

    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/types"
    "k8s.io/client-go/kubernetes/scheme"
    "k8s.io/client-go/tools/remotecommand"
    
    "istio.io/istio/pkg/log"
)

func (c *Controller) triggerReconfiguration(namespace string) error {
    log.Infof("Starting reconfiguration for namespace: %s", namespace)
    
    // Get all pods in the namespace
    pods, err := c.client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return fmt.Errorf("failed to list pods: %v", err)
    }

    // Trigger reconfiguration for each pod
    for _, pod := range pods.Items {
        if err := c.restartEnvoy(&pod); err != nil {
            log.Errorf("Failed to restart pod %s: %v", pod.Name, err)
            continue
        }
        log.Infof("Successfully triggered reconfiguration for pod: %s", pod.Name)
    }
    return nil
}

func (c *Controller) restartEnvoy(pod *corev1.Pod) error {
    timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
    
    // Update pod annotations
    patchData := fmt.Sprintf(`{
        "metadata": {
            "annotations": {
                "sidecar.istio.io/reloadConfig": "%s",
                "sidecar.istio.io/reloadTimestamp": "%s",
                "istio.io/forceReload": "true"
            }
        }
    }`, timestamp, timestamp)
    
    _, err := c.client.CoreV1().Pods(pod.Namespace).Patch(
        context.TODO(),
        pod.Name,
        types.StrategicMergePatchType,
        []byte(patchData),
        metav1.PatchOptions{},
    )
    
    if err != nil {
        return fmt.Errorf("failed to patch pod %s: %v", pod.Name, err)
    }
    
    cmd := []string{
        "pilot-agent",
        "request",
        "POST",
        "/quitquitquit",
    }
    
    exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", c.client.CoreV1().RESTClient().Post().
        Resource("pods").
        Name(pod.Name).
        Namespace(pod.Namespace).
        SubResource("exec").
        VersionedParams(&corev1.PodExecOptions{
            Container: "istio-proxy",
            Command:   cmd,
            Stdin:    false,
            Stdout:   true,
            Stderr:   true,
        }, scheme.ParameterCodec).URL())
    
    if err != nil {
        return fmt.Errorf("failed to create executor: %v", err)
    }
    
    var stdout, stderr bytes.Buffer
    err = exec.Stream(remotecommand.StreamOptions{
        Stdout: &stdout,
        Stderr: &stderr,
    })
    
    if err != nil {
        return fmt.Errorf("failed to execute command: %v", err)
    }
    
    // Wait for envoy to restart
    time.Sleep(5 * time.Second)
    
    return nil
}