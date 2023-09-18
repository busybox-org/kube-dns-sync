package main

import (
	"os"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/xmapst/kube-dns-sync/internal/core"
)

var (
	cmd = &cobra.Command{
		Use:               os.Args[0],
		Short:             "The kubernetes ingress domain name automatically adds dns resolution",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			svc, err := service.New(new(core.Program), &service.Config{
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
	cmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "d", false, "Enable debug mode.\nDefault: false")
	cmd.PersistentFlags().StringVarP(&core.KubeConf, "config", "c", "", "Manually specify the configuration cluster file.\nDefault: use service account")
	cmd.PersistentFlags().StringVarP(&core.DefaultDnsType, "default.dns_type", "", "", "Default dns provider provider")
	cmd.PersistentFlags().StringVarP(&core.DefaultAK, "default.ak", "", "", "AK authentication of the default dns provider provider")
	cmd.PersistentFlags().StringVarP(&core.DefaultSK, "default.sk", "", "", "SK authentication of the default dns provider provider")
	cmd.PersistentFlags().StringVarP(&core.HttpProxy, "proxy", "", "", "Use proxy to add dns resolution")
	cmd.PersistentFlags().StringVarP(&core.DNSServer, "dns", "", "", "dns server")
}

func main() {
	cobra.CheckErr(cmd.Execute())
}
