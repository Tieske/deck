package file

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"

	kicv1 "github.com/kong/kubernetes-ingress-controller/v2/pkg/apis/configuration/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8snetv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func KongToKIC(content *Content) ([]byte, error) {

	file := &KICContent{}
	var err error

	err = populateKICKongClusterPlugins(content, file)
	if err != nil {
		return nil, err
	}

	err = populateKICServicesAndIngresses(content, file)
	if err != nil {
		return nil, err
	}

	err = populateKICConsumers(content, file)
	if err != nil {
		return nil, err
	}

	return file.marshalKICContent()
}
func populateKICKongClusterPlugins(content *Content, file *KICContent) error {

	// Global Plugins map to KongClusterPlugins
	// iterate content.Plugins and copy them into kicv1.KongPlugin manifests
	// add the kicv1.KongPlugin to the KICContent.KongClusterPlugins slice
	for _, plugin := range content.Plugins {
		var kongPlugin kicv1.KongClusterPlugin
		kongPlugin.APIVersion = "configuration.konghq.com/v1"
		kongPlugin.Kind = "KongClusterPlugin"
		if plugin.InstanceName != nil {
			kongPlugin.ObjectMeta.Name = *plugin.InstanceName
		}
		kongPlugin.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		if plugin.Name != nil {
			kongPlugin.PluginName = *plugin.Name
		}

		// transform the plugin config from map[string]interface{} to apiextensionsv1.JSON
		var configJSON apiextensionsv1.JSON
		var err error
		configJSON.Raw, err = json.Marshal(plugin.Config)
		if err != nil {
			return err
		}
		kongPlugin.Config = configJSON
		file.KongClusterPlugins = append(file.KongClusterPlugins, kongPlugin)
	}
	return nil
}

func populateKICServicesAndIngresses(content *Content, file *KICContent) error {

	// Kong Services map to K8s Services. Kong Routes map to K8s Ingresses.
	// To specify Kong specific features, K8s Ingress and Service resources
	// will eventually have a KongIngress resource associated to them.

	// Iterate Kong Services and create k8s Services
	for _, service := range content.Services {
		var k8sService k8scorev1.Service
		var protocol k8scorev1.Protocol

		k8sService.TypeMeta.APIVersion = "v1"
		k8sService.TypeMeta.Kind = "Service"
		if service.Name != nil {
			k8sService.ObjectMeta.Name = *service.Name
		} else {
			log.Println("Service without a name is not recommended")
		}
		k8sService.ObjectMeta.Annotations = make(map[string]string)

		// default TCP unless service.Protocol is equal to k8scorev1.ProtocolUDP
		if service.Protocol != nil && k8scorev1.Protocol(strings.ToUpper(*service.Protocol)) == k8scorev1.ProtocolUDP {
			protocol = k8scorev1.ProtocolUDP
		} else {
			protocol = k8scorev1.ProtocolTCP
		}

		if service.Port != nil {
			sPort := k8scorev1.ServicePort{
				Protocol:   protocol,
				Port:       int32(*service.Port),
				TargetPort: intstr.IntOrString{IntVal: int32(*service.Port)},
			}
			k8sService.Spec.Ports = append(k8sService.Spec.Ports, sPort)
		}

		if service.Name != nil {
			k8sService.Spec.Selector = map[string]string{"app": *service.Name}
		} else {
			log.Println("Service without a name is not recommended")
		}

		populateKICUpstreams(content, &service, &k8sService, file)

		err := populateKICIngresses(&service, file)
		if err != nil {
			return err
		}

		// iterate over the plugins for this service, create a KongPlugin for each one and add an annotation to the service

		for _, plugin := range service.Plugins {
			var kongPlugin kicv1.KongPlugin
			kongPlugin.APIVersion = "configuration.konghq.com/v1"
			kongPlugin.Kind = "KongPlugin"
			if plugin.Name != nil {
				kongPlugin.ObjectMeta.Name = *plugin.Name
			}
			kongPlugin.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
			kongPlugin.PluginName = *plugin.Name

			// transform the plugin config from map[string]interface{} to apiextensionsv1.JSON
			var configJSON apiextensionsv1.JSON
			var err error
			configJSON.Raw, err = json.Marshal(plugin.Config)
			if err != nil {
				return err
			}
			kongPlugin.Config = configJSON

			// create a plugins annotation in the k8sservice to link the plugin to it
			k8sService.ObjectMeta.Annotations["konghq.com/plugins"] = kongPlugin.ObjectMeta.Name

			file.KongPlugins = append(file.KongPlugins, kongPlugin)
		}

		file.Services = append(file.Services, k8sService)

	}
	return nil
}

func populateKICUpstreams(content *Content, service *FService, k8sservice *k8scorev1.Service, file *KICContent) {

	// add Kong specific configuration to the k8s service via a KongIngress resource

	var kongIngress kicv1.KongIngress
	kongIngress.APIVersion = "configuration.konghq.com/v1"
	kongIngress.Kind = "KongIngress"
	kongIngress.ObjectMeta.Name = *service.Name
	kongIngress.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}

	// add an annotation to the k8sservice to link this kongIngress to it
	k8sservice.ObjectMeta.Annotations["konghq.com/override"] = kongIngress.ObjectMeta.Name

	// proxy attributes from the service to the kongIngress
	kongIngress.Proxy = &kicv1.KongIngressService{
		Protocol:       service.Protocol,
		Path:           service.Path,
		Retries:        service.Retries,
		ConnectTimeout: service.ConnectTimeout,
		WriteTimeout:   service.WriteTimeout,
		ReadTimeout:    service.ReadTimeout,
	}

	// Find the upstream (if any) whose name matches the service host and copy the upstream
	// into a kicv1.KongIngress resource. Append the kicv1.KongIngress to kicContent.KongIngresses.
	for _, upstream := range content.Upstreams {
		if upstream.Name != nil && strings.EqualFold(*upstream.Name, *service.Host) {
			kongIngress.Upstream = &kicv1.KongIngressUpstream{
				HostHeader:             upstream.HostHeader,
				Algorithm:              upstream.Algorithm,
				Slots:                  upstream.Slots,
				Healthchecks:           upstream.Healthchecks,
				HashOn:                 upstream.HashOn,
				HashFallback:           upstream.HashFallback,
				HashOnHeader:           upstream.HashOnHeader,
				HashFallbackHeader:     upstream.HashFallbackHeader,
				HashOnCookie:           upstream.HashOnCookie,
				HashOnCookiePath:       upstream.HashOnCookiePath,
				HashOnQueryArg:         upstream.HashOnQueryArg,
				HashFallbackQueryArg:   upstream.HashFallbackQueryArg,
				HashOnURICapture:       upstream.HashOnURICapture,
				HashFallbackURICapture: upstream.HashFallbackURICapture,
			}
		}
	}
	file.KongIngresses = append(file.KongIngresses, kongIngress)
}

func populateKICIngresses(service *FService, file *KICContent) error {
	// Transform routes into k8s Ingress and KongIngress resources
	// Assume each pair host/path will get its own ingress manifest
	for _, route := range service.Routes {
		// save all ingresses we create for this route so we can then
		// assign them the plugins for this route
		var routeIngresses []k8snetv1.Ingress

		// if there are no hosts just use the paths
		if len(route.Hosts) == 0 {
			routeIngresses = routePathToIngress(route, nil, service, routeIngresses, file)
		} else {
			// iterate over the hosts and paths and create an ingress for each

			for _, host := range route.Hosts {
				//  create a KongIngress resource and copy route data into it
				// add annotation to the ingress to link it to the kongIngress
				routeIngresses = routePathToIngress(route, host, service, routeIngresses, file)

			}
		}
		for _, plugin := range route.Plugins {
			var kongPlugin kicv1.KongPlugin
			kongPlugin.APIVersion = "configuration.konghq.com/v1"
			kongPlugin.Kind = "KongPlugin"
			if plugin.Name != nil {
				kongPlugin.ObjectMeta.Name = *plugin.Name
			}
			kongPlugin.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
			kongPlugin.PluginName = *plugin.Name

			// transform the plugin config from map[string]interface{} to apiextensionsv1.JSON
			var configJSON apiextensionsv1.JSON
			var err error
			configJSON.Raw, err = json.Marshal(plugin.Config)
			if err != nil {
				return err
			}
			kongPlugin.Config = configJSON

			// create a plugins annotation in the routeIngresses to link them to this plugin.
			// separate plugins with commas
			for _, k8sIngress := range routeIngresses {
				if k8sIngress.ObjectMeta.Annotations["konghq.com/plugins"] == "" {
					k8sIngress.ObjectMeta.Annotations["konghq.com/plugins"] = kongPlugin.PluginName
				} else {
					k8sIngress.ObjectMeta.Annotations["konghq.com/plugins"] = k8sIngress.ObjectMeta.Annotations["konghq.com/plugins"] + "," + kongPlugin.PluginName
				}
			}

			file.KongPlugins = append(file.KongPlugins, kongPlugin)
		}
	}
	return nil
}

func routePathToIngress(route *FRoute, host *string, service *FService, routeIngresses []k8snetv1.Ingress, file *KICContent) []k8snetv1.Ingress {
	for _, path := range route.Paths {
		var k8sIngress k8snetv1.Ingress
		var pathTypeImplSpecific k8snetv1.PathType = k8snetv1.PathTypeImplementationSpecific
		k8sIngress.TypeMeta.APIVersion = "networking.k8s.io/v1"
		k8sIngress.TypeMeta.Kind = "Ingress"
		k8sIngress.ObjectMeta.Name = *route.Name
		ingressClassName := "kong"
		k8sIngress.Spec.IngressClassName = &ingressClassName
		

		// Host and/or Service.Port can be nil. There are 4 possible combinations.
		if host != nil && service.Port != nil {
			k8sIngress.Spec.Rules = append(k8sIngress.Spec.Rules, k8snetv1.IngressRule{
				Host: *host,
				IngressRuleValue: k8snetv1.IngressRuleValue{
					HTTP: &k8snetv1.HTTPIngressRuleValue{
						Paths: []k8snetv1.HTTPIngressPath{
							{
								Path:     *path,
								PathType: &pathTypeImplSpecific,
								Backend: k8snetv1.IngressBackend{
									Service: &k8snetv1.IngressServiceBackend{
										Name: *service.Name,
										Port: k8snetv1.ServiceBackendPort{
											Number: int32(*service.Port),
										},
									},
								},
							},
						},
					},
				},
			})
		} else if host == nil && service.Port != nil {
			k8sIngress.Spec.Rules = append(k8sIngress.Spec.Rules, k8snetv1.IngressRule{
				IngressRuleValue: k8snetv1.IngressRuleValue{
					HTTP: &k8snetv1.HTTPIngressRuleValue{
						Paths: []k8snetv1.HTTPIngressPath{
							{
								Path:     *path,
								PathType: &pathTypeImplSpecific,
								Backend: k8snetv1.IngressBackend{
									Service: &k8snetv1.IngressServiceBackend{
										Name: *service.Name,
										Port: k8snetv1.ServiceBackendPort{
											Number: int32(*service.Port),
										},
									},
								},
							},
						},
					},
				},
			})
		} else if host != nil && service.Port == nil {
			k8sIngress.Spec.Rules = append(k8sIngress.Spec.Rules, k8snetv1.IngressRule{
				Host: *host,
				IngressRuleValue: k8snetv1.IngressRuleValue{
					HTTP: &k8snetv1.HTTPIngressRuleValue{
						Paths: []k8snetv1.HTTPIngressPath{
							{
								Path: *path,
								PathType: &pathTypeImplSpecific,
								Backend: k8snetv1.IngressBackend{
									Service: &k8snetv1.IngressServiceBackend{
										Name: *service.Name,
									},
								},
							},
						},
					},
				},
			})
		} else {
			// host == nil && service.Port == nil
			k8sIngress.Spec.Rules = append(k8sIngress.Spec.Rules, k8snetv1.IngressRule{
				IngressRuleValue: k8snetv1.IngressRuleValue{
					HTTP: &k8snetv1.HTTPIngressRuleValue{
						Paths: []k8snetv1.HTTPIngressPath{
							{
								Path: *path,
								PathType: &pathTypeImplSpecific,
								Backend: k8snetv1.IngressBackend{
									Service: &k8snetv1.IngressServiceBackend{
										Name: *service.Name,
									},
								},
							},
						},
					},
				},
			})
		}


		// Create a KongIngress resource and copy Kong specific route data into it
		var kongIngress kicv1.KongIngress
		kongIngress.APIVersion = "configuration.konghq.com/v1"
		kongIngress.Kind = "KongIngress"
		kongIngress.ObjectMeta.Name = *route.Name
		kongIngress.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}

		var kongProtocols []*kicv1.KongProtocol
		for _, protocol := range route.Protocols {
			p := kicv1.KongProtocol(*protocol)
			kongProtocols = append(kongProtocols, &p)
		}

		kongIngress.Route = &kicv1.KongIngressRoute{
			Methods:                 route.Methods,
			Protocols:               kongProtocols,
			StripPath:               route.StripPath,
			PreserveHost:            route.PreserveHost,
			RegexPriority:           route.RegexPriority,
			HTTPSRedirectStatusCode: route.HTTPSRedirectStatusCode,
			Headers:                 route.Headers,
			PathHandling:            route.PathHandling,
			SNIs:                    route.SNIs,
			RequestBuffering:        route.RequestBuffering,
			ResponseBuffering:       route.ResponseBuffering,
		}

		// add an annotation to the k8sIngress to link it to the kongIngress
		k8sIngress.ObjectMeta.Annotations = map[string]string{"konghq.com/override": kongIngress.ObjectMeta.Name}

		routeIngresses = append(routeIngresses, k8sIngress)

		file.Ingresses = append(file.Ingresses, k8sIngress)
		file.KongIngresses = append(file.KongIngresses, kongIngress)
	}
	return routeIngresses
}

func populateKICConsumers(content *Content, file *KICContent) error {
	// Iterate Kong Consumers and copy them into KongConsumer
	for _, consumer := range content.Consumers {
		var kongConsumer kicv1.KongConsumer
		kongConsumer.APIVersion = "configuration.konghq.com/v1"
		kongConsumer.Kind = "KongConsumer"
		kongConsumer.ObjectMeta.Name = *consumer.Username
		kongConsumer.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		kongConsumer.Username = *consumer.Username
		if consumer.CustomID != nil {
			kongConsumer.CustomID = *consumer.CustomID
		}

		populateKICKeyAuthSecrets(&consumer, &kongConsumer, file)
		populateKICHMACSecrets(&consumer, &kongConsumer, file)
		populateKICJWTAuthSecrets(&consumer, &kongConsumer, file)
		populateKICBasicAuthSecrets(&consumer, &kongConsumer, file)
		populateKICOAuth2CredSecrets(&consumer, &kongConsumer, file)
		populateKICACLGroupSecrets(&consumer, &kongConsumer, file)
		populateKICMTLSAuthSecrets(&consumer, &kongConsumer, file)

		// for each consumer.plugin, create a KongPlugin and a plugin annotation in the kongConsumer
		// to link the plugin
		for _, plugin := range consumer.Plugins {
			var kongPlugin kicv1.KongPlugin
			kongPlugin.APIVersion = "configuration.konghq.com/v1"
			kongPlugin.Kind = "KongPlugin"
			if plugin.InstanceName != nil {
				kongPlugin.ObjectMeta.Name = *plugin.InstanceName
			}
			kongPlugin.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
			if plugin.Name != nil {
				kongPlugin.PluginName = *plugin.Name
			}

			// transform the plugin config from map[string]interface{} to apiextensionsv1.JSON
			var configJSON apiextensionsv1.JSON
			var err error
			configJSON.Raw, err = json.Marshal(plugin.Config)
			if err != nil {
				return err
			}
			kongPlugin.Config = configJSON
			file.KongPlugins = append(file.KongPlugins, kongPlugin)

			kongConsumer.ObjectMeta.Annotations["konghq.com/plugins"] = kongPlugin.ObjectMeta.Name
		}

		file.KongConsumers = append(file.KongConsumers, kongConsumer)
	}

	return nil
}

func populateKICMTLSAuthSecrets(consumer *FConsumer, kongConsumer *kicv1.KongConsumer, file *KICContent) {
	// iterate consumer.MTLSAuths and copy them into k8scorev1.Secret, then add them to kicContent.Secrets
	for _, mtlsAuth := range consumer.MTLSAuths {
		var secret k8scorev1.Secret
		var secretName = "mtls-auth-" + *consumer.Username
		secret.TypeMeta.APIVersion = "v1"
		secret.TypeMeta.Kind = "Secret"
		secret.Type = "Opaque"
		secret.ObjectMeta.Name = strings.ToLower(secretName)
		secret.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		secret.ObjectMeta.Labels = map[string]string{"konghq.com/ca-cert": "true"}
		secret.StringData = make(map[string]string)
		secret.StringData["kongCredType"] = "mtls-auth"

		if mtlsAuth.SubjectName != nil {
			secret.StringData["subject_name"] = *mtlsAuth.SubjectName
		}

		if mtlsAuth.ID != nil {
			secret.StringData["id"] = *mtlsAuth.ID
		}

		if mtlsAuth.CACertificate != nil && mtlsAuth.CACertificate.Cert != nil {
			secret.StringData["cert"] = *mtlsAuth.CACertificate.Cert
		}

		if mtlsAuth.CACertificate != nil && mtlsAuth.CACertificate.CertDigest != nil {
			secret.StringData["cert_digest"] = *mtlsAuth.CACertificate.CertDigest
		}

		// add the secret name to the kongConsumer.credentials
		kongConsumer.Credentials = append(kongConsumer.Credentials, secretName)

		file.Secrets = append(file.Secrets, secret)
	}
}

func populateKICACLGroupSecrets(consumer *FConsumer, kongConsumer *kicv1.KongConsumer, file *KICContent) {
	// iterate consumer.ACLGroups and copy them into k8scorev1.Secret, then add them to kicContent.Secrets
	for _, aclGroup := range consumer.ACLGroups {
		var secret k8scorev1.Secret
		var secretName = "acl-group-" + *consumer.Username
		secret.TypeMeta.APIVersion = "v1"
		secret.TypeMeta.Kind = "Secret"
		secret.ObjectMeta.Name = strings.ToLower(secretName)
		secret.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		secret.StringData = make(map[string]string)

		secret.StringData["kongCredType"] = "acl"
		if aclGroup.Group != nil {
			secret.StringData["group"] = *aclGroup.Group
		}

		// add the secret name to the kongConsumer.credentials
		kongConsumer.Credentials = append(kongConsumer.Credentials, secretName)

		file.Secrets = append(file.Secrets, secret)
	}
}

func populateKICOAuth2CredSecrets(consumer *FConsumer, kongConsumer *kicv1.KongConsumer, file *KICContent) {
	// iterate consumer.OAuth2Creds and copy them into k8scorev1.Secret, then add them to kicContent.Secrets
	for _, oauth2Cred := range consumer.Oauth2Creds {
		var secret k8scorev1.Secret
		var secretName = "oauth2cred-" + *consumer.Username
		secret.TypeMeta.APIVersion = "v1"
		secret.TypeMeta.Kind = "Secret"
		secret.ObjectMeta.Name = strings.ToLower(secretName)
		secret.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		secret.StringData = make(map[string]string)
		secret.StringData["kongCredType"] = "oauth2"

		if oauth2Cred.Name != nil {
			secret.StringData["name"] = *oauth2Cred.Name
		}

		if oauth2Cred.ClientID != nil {
			secret.StringData["client_id"] = *oauth2Cred.ClientID
		}

		if oauth2Cred.ClientSecret != nil {
			secret.StringData["client_secret"] = *oauth2Cred.ClientSecret
		}

		if oauth2Cred.ClientType != nil {
			secret.StringData["client_type"] = *oauth2Cred.ClientType
		}

		if oauth2Cred.HashSecret != nil {
			secret.StringData["hash_secret"] = strconv.FormatBool(*oauth2Cred.HashSecret)
		}

		// add the secret name to the kongConsumer.credentials
		kongConsumer.Credentials = append(kongConsumer.Credentials, secretName)

		file.Secrets = append(file.Secrets, secret)
	}
}

func populateKICBasicAuthSecrets(consumer *FConsumer, kongConsumer *kicv1.KongConsumer, file *KICContent) {
	// iterate consumer.BasicAuths and copy them into k8scorev1.Secret, then add them to kicContent.Secrets
	for _, basicAuth := range consumer.BasicAuths {
		var secret k8scorev1.Secret
		var secretName = "basic-auth-" + *consumer.Username
		secret.TypeMeta.APIVersion = "v1"
		secret.TypeMeta.Kind = "Secret"
		secret.ObjectMeta.Name = strings.ToLower(secretName)
		secret.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		secret.StringData = make(map[string]string)
		secret.StringData["kongCredType"] = "basic-auth"

		if basicAuth.Username != nil {
			secret.StringData["username"] = *basicAuth.Username
		}
		if basicAuth.Password != nil {
			secret.StringData["password"] = *basicAuth.Password
		}

		// add the secret name to the kongConsumer.credentials
		kongConsumer.Credentials = append(kongConsumer.Credentials, secretName)

		file.Secrets = append(file.Secrets, secret)
	}
}

func populateKICJWTAuthSecrets(consumer *FConsumer, kongConsumer *kicv1.KongConsumer, file *KICContent) {
	// iterate consumer.JWTAuths and copy them into k8scorev1.Secret, then add them to kicContent.Secrets
	for _, jwtAuth := range consumer.JWTAuths {
		var secret k8scorev1.Secret
		var secretName = "jwt-auth-" + *consumer.Username
		secret.TypeMeta.APIVersion = "v1"
		secret.TypeMeta.Kind = "Secret"
		secret.ObjectMeta.Name = strings.ToLower(secretName)
		secret.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		secret.StringData = make(map[string]string)
		secret.StringData["kongCredType"] = "jwt"

		// only do the following assignments if not null
		if jwtAuth.Key != nil {
			secret.StringData["key"] = *jwtAuth.Key
		}

		if jwtAuth.Algorithm != nil {
			secret.StringData["algorithm"] = *jwtAuth.Algorithm
		}

		if jwtAuth.RSAPublicKey != nil {
			secret.StringData["rsa_public_key"] = *jwtAuth.RSAPublicKey
		}

		if jwtAuth.Secret != nil {
			secret.StringData["secret"] = *jwtAuth.Secret
		}

		// add the secret name to the kongConsumer.credentials
		kongConsumer.Credentials = append(kongConsumer.Credentials, secretName)

		file.Secrets = append(file.Secrets, secret)
	}
}

func populateKICHMACSecrets(consumer *FConsumer, kongConsumer *kicv1.KongConsumer, file *KICContent) {
	// iterate consumer.HMACAuths and copy them into k8scorev1.Secret, then add them to kicContent.Secrets
	for _, hmacAuth := range consumer.HMACAuths {
		var secret k8scorev1.Secret
		var secretName = "hmac-auth-" + *consumer.Username
		secret.TypeMeta.APIVersion = "v1"
		secret.TypeMeta.Kind = "Secret"
		secret.ObjectMeta.Name = strings.ToLower(secretName)
		secret.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		secret.StringData = make(map[string]string)
		secret.StringData["kongCredType"] = "hmac-auth"

		if hmacAuth.Username != nil {
			secret.StringData["username"] = *hmacAuth.Username
		}

		if hmacAuth.Secret != nil {
			secret.StringData["secret"] = *hmacAuth.Secret
		}

		// add the secret name to the kongConsumer.credentials
		kongConsumer.Credentials = append(kongConsumer.Credentials, secretName)

		file.Secrets = append(file.Secrets, secret)
	}
}

func populateKICKeyAuthSecrets(consumer *FConsumer, kongConsumer *kicv1.KongConsumer, file *KICContent) {
	// iterate consumer.KeyAuths and copy them into k8scorev1.Secret, then add them to kicContent.Secrets
	// add the secret name to the kongConsumer.credentials
	for _, keyAuth := range consumer.KeyAuths {
		var secret k8scorev1.Secret
		var secretName = "key-auth-" + *consumer.Username
		secret.TypeMeta.APIVersion = "v1"
		secret.TypeMeta.Kind = "Secret"
		secret.ObjectMeta.Name = strings.ToLower(secretName)
		secret.ObjectMeta.Annotations = map[string]string{"kubernetes.io/ingress.class": "kong"}
		secret.StringData = make(map[string]string)
		secret.StringData["kongCredType"] = "key-auth"

		if keyAuth.Key != nil {
			secret.StringData["key"] = *keyAuth.Key
		}

		kongConsumer.Credentials = append(kongConsumer.Credentials, secretName)

		file.Secrets = append(file.Secrets, secret)

	}
}
