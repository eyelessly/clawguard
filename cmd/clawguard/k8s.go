package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type annotationFilter struct {
	key string
	val string
}

// parseAnnotationFilter parses CLAWGUARD_POD_ANNOTATION as key=value (single pair).
// Default: clawguard.io/monitor=true
func parseAnnotationFilter(env string) (annotationFilter, error) {
	env = strings.TrimSpace(env)
	if env == "" {
		return annotationFilter{key: "clawguard.io/monitor", val: "true"}, nil
	}
	i := strings.IndexByte(env, '=')
	if i <= 0 {
		return annotationFilter{}, fmt.Errorf("CLAWGUARD_POD_ANNOTATION %q: want key=value", env)
	}
	key := strings.TrimSpace(env[:i])
	val := strings.TrimSpace(env[i+1:])
	if key == "" {
		return annotationFilter{}, fmt.Errorf("CLAWGUARD_POD_ANNOTATION: empty key")
	}
	return annotationFilter{key: key, val: val}, nil
}

func (f annotationFilter) matches(annotations map[string]string) bool {
	if annotations == nil {
		return false
	}
	v, ok := annotations[f.key]
	return ok && v == f.val
}

func inClusterOrKubeconfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func newK8sClient() (*kubernetes.Clientset, error) {
	cfg, err := inClusterOrKubeconfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func (cw *containerWatch) runK8sMode(ctx context.Context) error {
	ann, err := parseAnnotationFilter(os.Getenv("CLAWGUARD_POD_ANNOTATION"))
	if err != nil {
		return err
	}
	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if nodeName == "" {
		return fmt.Errorf("NODE_NAME is required in Kubernetes mode (Downward API)")
	}

	clientset, err := newK8sClient()
	if err != nil {
		return fmt.Errorf("k8s client: %w", err)
	}

	log.Printf("K8s mode: node=%s annotation filter %s=%s", nodeName, ann.key, ann.val)

	if err := cw.scanRunningPods(ctx, clientset, nodeName, ann); err != nil {
		log.Printf("initial pod scan: %v", err)
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := cw.watchPods(ctx, clientset, nodeName, ann); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("pod watch ended: %v; retrying in 3s", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (cw *containerWatch) scanRunningPods(ctx context.Context, cs *kubernetes.Clientset, nodeName string, ann annotationFilter) error {
	list, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return err
	}
	for i := range list.Items {
		cw.syncPod(ctx, &list.Items[i], ann)
	}
	return nil
}

func (cw *containerWatch) watchPods(ctx context.Context, cs *kubernetes.Clientset, nodeName string, ann annotationFilter) error {
	w, err := cs.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return err
	}
	defer w.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.ResultChan():
			if !ok {
				return fmt.Errorf("watch channel closed")
			}
			pod, ok := ev.Object.(*corev1.Pod)
			if !ok || pod == nil {
				continue
			}
			switch ev.Type {
			case watch.Added, watch.Modified:
				cw.syncPod(ctx, pod, ann)
			case watch.Deleted:
				cw.detachPodContainers(pod)
			}
		}
	}
}

func (cw *containerWatch) syncPod(ctx context.Context, pod *corev1.Pod, ann annotationFilter) {
	if pod.DeletionTimestamp != nil {
		cw.detachPodContainers(pod)
		return
	}
	if !ann.matches(pod.Annotations) {
		return
	}
	if pod.Status.Phase != corev1.PodRunning {
		return
	}

	for _, st := range pod.Status.ContainerStatuses {
		if st.ContainerID == "" || st.State.Running == nil {
			continue
		}
		runtime, cid := splitContainerID(st.ContainerID)
		if cid == "" {
			continue
		}
		if cw.isSelfContainer(cid) {
			continue
		}
		meta := targetMeta{
			podName:       pod.Name,
			podNamespace:  pod.Namespace,
			runtime:       runtime,
			containerName: st.Name,
		}
		cw.attachByContainerID(ctx, cid, meta)
	}
}

func (cw *containerWatch) detachPodContainers(pod *corev1.Pod) {
	for _, st := range pod.Status.ContainerStatuses {
		_, cid := splitContainerID(st.ContainerID)
		if cid == "" {
			continue
		}
		cw.detachContainer(cid)
	}
	// Also detach by any key we stored under short/full ID for this pod.
	cw.mu.Lock()
	var ids []string
	for id, meta := range cw.metaByID {
		if meta.podName == pod.Name && meta.podNamespace == pod.Namespace {
			ids = append(ids, id)
		}
	}
	cw.mu.Unlock()
	for _, id := range ids {
		cw.detachContainer(id)
	}
}

func splitContainerID(raw string) (runtime, id string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		return raw[:i], strings.TrimPrefix(strings.ToLower(raw[i+3:]), "sha256:")
	}
	return "", strings.TrimPrefix(strings.ToLower(raw), "sha256:")
}

// attachByContainerID resolves a host PID for the container then attaches uprobes.
func (cw *containerWatch) attachByContainerID(ctx context.Context, containerID string, meta targetMeta) {
	cw.mu.Lock()
	if _, ok := cw.byID[containerID]; ok {
		cw.metaByID[containerID] = meta
		cw.mu.Unlock()
		return
	}
	// Also skip if already attached under a prefix-matching key.
	for id := range cw.byID {
		if containerIDsMatch(id, containerID) {
			cw.metaByID[id] = meta
			cw.mu.Unlock()
			return
		}
	}
	cw.mu.Unlock()

	pid, err := findPIDByContainerID(containerID)
	if err != nil {
		debugLog("k8s attach: pid for %s: %v (retry shortly)", shortID(containerID), err)
		// Retry a few times - container may have just started.
		const maxAttempts = 30
		for attempt := 0; attempt < maxAttempts; attempt++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			pid, err = findPIDByContainerID(containerID)
			if err == nil && pid > 0 {
				break
			}
		}
		if err != nil || pid <= 0 {
			log.Printf("container %s: resolve pid: %v", shortID(containerID), err)
			recordAttachError()
			return
		}
	}

	cw.attachUprobes(ctx, containerID, pid, meta)
}

// findPIDByContainerID scans /proc for a process whose cgroup path contains the container ID.
func findPIDByContainerID(containerID string) (int, error) {
	id := strings.ToLower(strings.TrimPrefix(containerID, "sha256:"))
	if len(id) < 12 {
		return 0, fmt.Errorf("container id too short: %q", containerID)
	}
	short := id
	if len(short) > 64 {
		short = short[:64]
	}
	needle12 := short
	if len(needle12) > 12 {
		needle12 = needle12[:12]
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name[0] < '1' || name[0] > '9' {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(name, "%d", &pid); err != nil || pid <= 1 {
			continue
		}
		cg, err := os.ReadFile(filepath.Join("/proc", name, "cgroup"))
		if err != nil {
			continue
		}
		s := strings.ToLower(string(cg))
		if strings.Contains(s, short) || strings.Contains(s, needle12) {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("no process cgroup matched container %s", shortID(id))
}

func containerIDsMatch(a, b string) bool {
	a = strings.ToLower(strings.TrimPrefix(a, "sha256:"))
	b = strings.ToLower(strings.TrimPrefix(b, "sha256:"))
	if a == b {
		return true
	}
	if len(a) >= 12 && len(b) >= 12 {
		return a[:12] == b[:12]
	}
	return false
}
