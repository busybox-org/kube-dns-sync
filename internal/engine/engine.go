package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kardianos/service"
	gocache "github.com/patrickmn/go-cache"
	"github.com/smallnest/chanx"
	"github.com/xmapst/kube-dns-sync/internal/dns"
	"github.com/xmapst/kube-dns-sync/internal/utils"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	listersnetworkingv1 "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/rest"
	kubecache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const (
	annotationEnable = "kubernetes.io/kube-dns-sync.enable"
	annotationType   = "kubernetes.io/kube-dns-sync.provider"
	annotationAK     = "kubernetes.io/kube-dns-sync.access_key"
	annotationSK     = "kubernetes.io/kube-dns-sync.access_secret"
	annotationArgs   = "kubernetes.io/kube-dns-sync.args"
	annotationProxy  = "kubernetes.io/kube-dns-sync.http_proxy"
	annotationIPV4   = "kubernetes.io/kube-dns-sync.enable_ipv4"
	annotationIPV6   = "kubernetes.io/kube-dns-sync.enable_ipv6"
	annotationDNS    = "kubernetes.io/kube-dns-sync.dns_server"
)

var (
	Debug          bool
	KubeConf       string
	DefaultDnsType string
	DefaultAK      string
	DefaultSK      string
	HttpProxy      string
	DNSServer      string
)

type Program struct {
	ctx                context.Context
	cancel             context.CancelFunc
	cache              *gocache.Cache
	client             *kubernetes.Clientset
	informerFactory    informers.SharedInformerFactory
	ingressInformer    kubecache.SharedIndexInformer
	ingressClassLister listersnetworkingv1.IngressClassLister
	serviceLister      listerscorev1.ServiceLister
	recvCh             *chanx.UnboundedChan[*networkingv1.Ingress]
}

func (p *Program) Start(_ service.Service) error {
	klog.Infoln("application is started")
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.recvCh = chanx.NewUnboundedChan[*networkingv1.Ingress](40960)

	// new cache in memory
	p.cache = gocache.New(5*time.Minute, 10*time.Minute)
	p.dispatch()

	// new kubernetes client
	if err := p.initKubeClient(); err != nil {
		return err
	}

	// The factory function of informer returns the sharedInformerFactory object
	p.informerFactory = informers.NewSharedInformerFactory(p.client, 15*time.Second)

	// Create the Informer of the ingress resource object
	p.ingressInformer = p.informerFactory.Networking().V1().Ingresses().Informer()
	p.ingressClassLister = p.informerFactory.Networking().V1().IngressClasses().Lister()
	p.serviceLister = p.informerFactory.Core().V1().Services().Lister()

	// wait for the Informer sync to complete
	p.informerFactory.WaitForCacheSync(p.ctx.Done())

	// Register event callback function
	_, err := p.ingressInformer.AddEventHandler(kubecache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item, ok := obj.(*networkingv1.Ingress)
			if !ok {
				klog.Warningln("Unexpected event type")
				return
			}
			if item.Spec.IngressClassName == nil {
				return
			}
			if enable, ok := item.Annotations[annotationEnable]; ok {
				if enable == "true" || enable == "on" {
					p.recvCh.In <- item
				}
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			item, ok := obj.(*networkingv1.Ingress)
			if !ok {
				klog.Warningln("Unexpected event type")
				return
			}
			if item.Spec.IngressClassName == nil {
				return
			}
			if enable, ok := item.Annotations[annotationEnable]; ok {
				if enable == "true" || enable == "on" {
					p.recvCh.In <- item
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			item, ok := obj.(*networkingv1.Ingress)
			if !ok {
				klog.Warningln("Unexpected event type")
				return
			}
			if item.Spec.IngressClassName == nil {
				return
			}
			if enable, ok := item.Annotations[annotationEnable]; ok {
				if enable == "true" || enable == "on" {
					p.recvCh.In <- item
				}
			}
		},
	})
	if err != nil {
		return err
	}

	// start Informer
	p.informerFactory.Start(p.ctx.Done())

	return nil
}

func (p *Program) Stop(_ service.Service) error {
	klog.Warningln("received signal, exiting...")
	p.cancel()
	return nil
}

func (p *Program) initKubeClient() error {
	var kubeConfig *rest.Config
	var err error
	if Debug {
		kubeConfPath := os.Getenv("KUBECONFIG")
		if kubeConfPath == "" {
			kubeConfPath = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
		var f []byte
		f, err = os.ReadFile(kubeConfPath)
		if err != nil {
			klog.Errorln(err)
			return err
		}
		kubeConfig, err = clientcmd.RESTConfigFromKubeConfig(f)
		if err != nil {
			klog.Errorln(err)
			return err
		}
	} else {
		kubeConfig, err = rest.InClusterConfig()
		if err != nil {
			klog.Errorln(err)
			return err
		}
	}
	// configure kubernetes client burst, qps, timeout parameter
	kubeConfig.Burst = 1000
	kubeConfig.QPS = 500
	kubeConfig.Timeout = 0

	// new kubernetes client
	p.client, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		klog.Errorln(err)
		return err
	}
	return nil
}

func (p *Program) dispatch() {
	go func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			case item := <-p.recvCh.Out:
				go p.consumer(item)
			}
		}
	}()
}

func (p *Program) consumer(item *networkingv1.Ingress) {
	proxy, ok := item.Annotations[annotationProxy]
	if !ok {
		proxy = HttpProxy
	}

	_dns, ok := item.Annotations[annotationDNS]
	if !ok {
		_dns = DNSServer
	}
	// get ingress controller svc
	controllerSvc, err := p.getIngressControllerSvc(item)
	if err != nil {
		return
	}
	if enable, ok := item.Annotations[annotationIPV4]; ok && enable == "true" {
		ipaddr, err := p.getIPV4Addr(proxy, _dns, controllerSvc)
		if err != nil {
			klog.Errorln(err)
			return
		}
		// Check ipv4 resolution
		err = p.checkResolution("IPV4", ipaddr, item)
		if err != nil {
			klog.Errorln(err)
		}
	}
	if enable, ok := item.Annotations[annotationIPV6]; ok && enable == "true" {
		ipaddr, err := p.getIPV6Addr(proxy, _dns, controllerSvc)
		if err != nil {
			return
		}
		// Check ipv6 resolution
		err = p.checkResolution("IPV6", ipaddr, item)
		if err != nil {
			klog.Errorln(err)
		}
	}
}

func (p *Program) getIngressControllerSvc(item *networkingv1.Ingress) (*v1.Service, error) {
	ingressClassName := *item.Spec.IngressClassName
	ingress, err := p.ingressClassLister.Get(ingressClassName)
	if err != nil {
		klog.Errorln(err)
		return nil, err
	}
	var set = labels.Set{}
	if instance, ok := ingress.Labels["app.kubernetes.io/instance"]; ok {
		set["app.kubernetes.io/instance"] = instance
	}

	if name, ok := ingress.Labels["app.kubernetes.io/name"]; ok {
		set["app.kubernetes.io/name"] = name
	}

	if len(set) == 0 {
		klog.Errorln("ingress-controller service not found")
		return nil, errors.New("ingress-controller service not found")
	}
	labelSelector := labels.SelectorFromSet(set)
	res, err := p.serviceLister.List(labelSelector)
	if err != nil {
		klog.Errorln(err)
		return nil, err
	}
	if len(res) == 0 {
		klog.Errorln("ingress-controller service not found")
		return nil, errors.New("ingress-controller service not found")
	}
	svc := res[0]
	return svc, nil
}

func (p *Program) getIPV4Addr(proxy, dns string, service *v1.Service) (string, error) {
	return p.getIP("IPV4", proxy, dns, service)
}

func (p *Program) getIPV6Addr(proxy, dns string, service *v1.Service) (string, error) {
	return p.getIP("IPV6", proxy, dns, service)
}

func (p *Program) getIP(t string, proxy, dns string, service *v1.Service) (string, error) {
	var result string
	switch service.Spec.Type {
	case corev1.ServiceTypeNodePort:
		if t == "IPV6" {
			result = p.getIpv6AddrFromUrl(proxy, dns)
		} else {
			result = p.getIpv4AddrFromUrl(proxy, dns)
		}
	case corev1.ServiceTypeLoadBalancer:
		var comp = Ipv4Reg
		if t == "IPV6" {
			comp = Ipv6Reg
		}
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			result = comp.FindString(ingress.IP)
			if result != "" {
				break
			}
		}
	}

	if result == "" {
		klog.Warningf("%s ip addr not found", t)
		return "", fmt.Errorf("%s ip addr not found", t)
	}
	return result, nil
}

var IPV6URL = []string{
	"https://6.ipw.cn",
	"https://speed.neu6.edu.cn/getIP.php",
	"https://v6.ident.me",
}

// Ipv6Reg IPv6正则
var Ipv6Reg = regexp.MustCompile(`((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))`)

func (p *Program) getIpv6AddrFromUrl(proxyAddr, dns string) (result string) {
	client := utils.CreateNoProxyHTTPClient("tcp6", dns)
	if proxyAddr != "" {
		client = utils.CreateProxyHTTPClient("tcp4", dns, proxyAddr)
		if Ipv6Reg.FindString(proxyAddr) != "" {
			client = utils.CreateProxyHTTPClient("tcp6", dns, proxyAddr)
		}
	}
	for _, _url := range IPV6URL {
		_url = strings.TrimSpace(_url)
		resp, err := client.Get(_url)
		if err != nil {
			klog.Errorln(err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			klog.Errorln(err)
			continue
		}
		_ = resp.Body.Close()
		result = Ipv6Reg.FindString(string(body))
		if result != "" {
			break
		}
	}
	return result
}

var IPV4URL = []string{
	"https://4.ipw.cn",
	"https://myip4.ipip.net",
	"https://ddns.oray.com/checkip",
	"https://ip.3322.net",
}

// Ipv4Reg IPv4正则
var Ipv4Reg = regexp.MustCompile(`((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])`)

func (p *Program) getIpv4AddrFromUrl(proxy, dns string) (result string) {
	client := utils.CreateNoProxyHTTPClient("tcp4", dns)
	if proxy != "" {
		client = utils.CreateProxyHTTPClient("tcp4", dns, proxy)
	}
	for _, _url := range IPV4URL {
		_url = strings.TrimSpace(_url)
		resp, err := client.Get(_url)
		if err != nil {
			klog.Errorln(err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			klog.Errorln(err)
			continue
		}
		_ = resp.Body.Close()
		result = Ipv4Reg.FindString(string(body))
		if result != "" {
			break
		}
	}
	return result
}

func (p *Program) checkResolution(t string, addr string, item *networkingv1.Ingress) error {
	for _, rule := range item.Spec.Rules {
		args, err := url.ParseQuery(item.Annotations[annotationArgs])
		if err != nil {
			klog.Warningln(err)
		}
		ak, ok := item.Annotations[annotationAK]
		if !ok {
			ak = DefaultAK
		}
		sk, ok := item.Annotations[annotationSK]
		if !ok {
			sk = DefaultSK
		}
		providerType, ok := item.Annotations[annotationType]
		if !ok {
			providerType = DefaultDnsType
		}
		p.resolution(&dns.Config{
			Provider: providerType,
			Ak:       ak,
			SK:       sk,
			Type:     t,
			Host:     rule.Host,
			Addr:     addr,
			Args:     args,
		})
	}
	return nil
}

func (p *Program) resolution(conf *dns.Config) {
	key := fmt.Sprintf("%s/%s", conf.Type, conf.Host)
	val, ok := p.cache.Get(key)
	if ok && val.(string) == conf.Addr {
		klog.Infof("Your IP %s has not changed, domain name %s", conf.Addr, conf.Host)
		// not thing to do
		return
	}
	provider, err := dns.New(conf.Provider)
	if err != nil {
		klog.Errorln(err)
		return
	}
	if err := provider.Init(conf); err != nil {
		klog.Errorln(err)
		return
	}
	if err := provider.AddUpdateDomainRecords(); err != nil {
		klog.Errorln(err)
		return
	}
	if !ok {
		if err := p.cache.Add(key, conf.Addr, gocache.NoExpiration); err != nil {
			klog.Errorln(err)
			return
		}
	}
	p.cache.Set(key, conf.Addr, gocache.NoExpiration)
}
