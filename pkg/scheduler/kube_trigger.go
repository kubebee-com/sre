package scheduler

import (
	"context"
	"errors"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var ErrKubernetesTriggerSourceConfiguration = errors.New("kubernetes trigger source configuration is invalid")

type TriggerSink interface {
	Enqueue(Trigger) bool
}

type KubernetesTriggerSourceOptions struct {
	Client       kubernetes.Interface
	Sink         TriggerSink
	Filter       func(Trigger) bool
	Namespace    string
	ResyncPeriod time.Duration
}

// KubernetesTriggerSource converts native Kubernetes informer callbacks into
// bounded scan triggers. It intentionally watches source objects rather than
// relying on admission webhooks: kubelet status transitions and controller
// generated Events are not admission requests.
type KubernetesTriggerSource struct {
	client       kubernetes.Interface
	sink         TriggerSink
	filter       func(Trigger) bool
	namespace    string
	resyncPeriod time.Duration
}

func NewKubernetesTriggerSource(options KubernetesTriggerSourceOptions) (*KubernetesTriggerSource, error) {
	if options.Client == nil || options.Sink == nil || options.ResyncPeriod < 0 {
		return nil, ErrKubernetesTriggerSourceConfiguration
	}
	return &KubernetesTriggerSource{
		client:       options.Client,
		sink:         options.Sink,
		filter:       options.Filter,
		namespace:    strings.TrimSpace(options.Namespace),
		resyncPeriod: options.ResyncPeriod,
	}, nil
}

func (s *KubernetesTriggerSource) Run(ctx context.Context) error {
	if s == nil || s.client == nil || s.sink == nil {
		return ErrKubernetesTriggerSourceConfiguration
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	options := make([]informers.SharedInformerOption, 0, 1)
	if s.namespace != "" {
		options = append(options, informers.WithNamespace(s.namespace))
	}
	factory := informers.NewSharedInformerFactoryWithOptions(s.client, s.resyncPeriod, options...)
	podInformer := factory.Core().V1().Pods().Informer()
	eventInformer := factory.Core().V1().Events().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { s.enqueuePod(watch.Added, obj) },
		UpdateFunc: func(_, obj interface{}) { s.enqueuePod(watch.Modified, obj) },
		DeleteFunc: func(obj interface{}) { s.enqueuePod(watch.Deleted, obj) },
	})
	eventInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { s.enqueueEvent(watch.Added, obj) },
		UpdateFunc: func(_, obj interface{}) { s.enqueueEvent(watch.Modified, obj) },
		DeleteFunc: func(obj interface{}) { s.enqueueEvent(watch.Deleted, obj) },
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced, eventInformer.HasSynced) {
		factory.Shutdown()
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrKubernetesTriggerSourceConfiguration
	}
	<-ctx.Done()
	factory.Shutdown()
	return ctx.Err()
}

func (s *KubernetesTriggerSource) enqueuePod(eventType watch.EventType, obj interface{}) {
	pod, ok := podFromInformerObject(obj)
	if !ok || pod.Name == "" {
		return
	}
	s.enqueue(Trigger{
		Resource:  "Pod",
		Namespace: pod.Namespace,
		Name:      pod.Name,
		EventType: string(eventType),
	})
}

func (s *KubernetesTriggerSource) enqueueEvent(eventType watch.EventType, obj interface{}) {
	event, ok := eventFromInformerObject(obj)
	if !ok || event.Name == "" {
		return
	}
	if event.Type != "" && !strings.EqualFold(event.Type, corev1.EventTypeWarning) {
		return
	}
	targetNamespace := strings.TrimSpace(event.InvolvedObject.Namespace)
	if targetNamespace == "" {
		targetNamespace = event.Namespace
	}
	s.enqueue(Trigger{
		Resource:        "Event",
		Namespace:       event.Namespace,
		Name:            event.Name,
		EventType:       string(eventType),
		TargetResource:  strings.TrimSpace(event.InvolvedObject.Kind),
		TargetNamespace: targetNamespace,
		TargetName:      strings.TrimSpace(event.InvolvedObject.Name),
	})
	if targetKind := strings.TrimSpace(event.InvolvedObject.Kind); targetKind != "" {
		if targetName := strings.TrimSpace(event.InvolvedObject.Name); targetName != "" {
			s.enqueue(Trigger{
				Resource:  targetKind,
				Namespace: targetNamespace,
				Name:      targetName,
				EventType: strings.ToUpper(strings.TrimSpace(event.Type)),
			})
		}
	}
}

func (s *KubernetesTriggerSource) enqueue(trigger Trigger) {
	if s == nil || s.sink == nil {
		return
	}
	if s.filter != nil && !s.filter(trigger) {
		return
	}
	s.sink.Enqueue(trigger)
}

func podFromInformerObject(obj interface{}) (*corev1.Pod, bool) {
	switch value := obj.(type) {
	case *corev1.Pod:
		return value, value != nil
	case cache.DeletedFinalStateUnknown:
		pod, ok := value.Obj.(*corev1.Pod)
		return pod, ok && pod != nil
	case *cache.DeletedFinalStateUnknown:
		if value == nil {
			return nil, false
		}
		pod, ok := value.Obj.(*corev1.Pod)
		return pod, ok && pod != nil
	default:
		return nil, false
	}
}

func eventFromInformerObject(obj interface{}) (*corev1.Event, bool) {
	switch value := obj.(type) {
	case *corev1.Event:
		return value, value != nil
	case cache.DeletedFinalStateUnknown:
		event, ok := value.Obj.(*corev1.Event)
		return event, ok && event != nil
	case *cache.DeletedFinalStateUnknown:
		if value == nil {
			return nil, false
		}
		event, ok := value.Obj.(*corev1.Event)
		return event, ok && event != nil
	default:
		return nil, false
	}
}
