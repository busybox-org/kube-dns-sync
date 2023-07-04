package main

import (
	"os"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"github.com/xmapst/kube-dns-sync/internal/engine"
	"k8s.io/klog/v2"
)

var (
	cmd = &cobra.Command{
		Use:               os.Args[0],
		Short:             "The kubernetes ingress domain name automatically adds dns resolution",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			svc, err := service.New(new(engine.Program), &service.Config{
				Name:        "kube-dns-sync",
				DisplayName: "kubernetes dns sync",
				Description: "The kubernetes ingress domain name automatically adds dns resolution",
			})
			if err != nil {
				klog.Fatalln(err)
			}
			err = svc.Run()
			if err != nil {
				klog.Fatalln(err)
			}
		},
	}
)

func init() {
	cmd.PersistentFlags().BoolVarP(&engine.Debug, "debug", "d", false, "Enable debug mode.\nDefault: false")
	cmd.PersistentFlags().StringVarP(&engine.KubeConf, "config", "c", "", "Manually specify the configuration cluster file.\nDefault: use service account")
	cmd.PersistentFlags().StringVarP(&engine.DefaultDnsType, "default.dns_type", "", "", "Default dns provider provider")
	cmd.PersistentFlags().StringVarP(&engine.DefaultAK, "default.ak", "", "", "AK authentication of the default dns provider provider")
	cmd.PersistentFlags().StringVarP(&engine.DefaultSK, "default.sk", "", "", "SK authentication of the default dns provider provider")
	cmd.PersistentFlags().StringVarP(&engine.HttpProxy, "http.proxy", "", "", "Use proxy to add dns resolution")
	cmd.PersistentFlags().StringVarP(&engine.DNSServer, "dns", "", "", "dns server")
}

func main() {
	cobra.CheckErr(cmd.Execute())
}
