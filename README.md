# kube-dns-sync

example:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/kube-dns-sync.enable: "true"
    kubernetes.io/kube-dns-sync.provider: "cloudflare"
    kubernetes.io/kube-dns-sync.access_secret: "xxxxxxxxxxxxx"
    kubernetes.io/kube-dns-sync.args: "proxied=true"
    kubernetes.io/kube-dns-sync.enable_ipv4: "true"
    kubernetes.io/kube-dns-sync.enable_ipv6: "true"
    traefik.ingress.kubernetes.io/router.tls: "true"
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
  name: test
  namespace: default
spec:
  ingressClassName: traefik
  tls:
  - hosts:
      - test.your-domain.com
    secretName: cloudflare-tls
  rules:
    - host: test.your-domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: test
                port:
                  number: 9999
```