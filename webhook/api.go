package webhook

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)


var (
	tlsCert string
	tlsKey  string
	port    int
	codecs  = serializer.NewCodecFactory(runtime.NewScheme())
	logger  = log.New(os.Stdout, "http: ", log.LstdFlags)
)

var rootCmd = &cobra.Command{
	Use:   "validating-webhook",
	Short: "loadbalancer service validating webhook",
	Long: `Example showing how to implement a basic validating webhook in Kubernetes.
Example:
$ validating-webhook --tls-cert <tls_cert> --tls-key <tls_key> --port <port>`,
	Run: func(cmd *cobra.Command, args []string) {
		if tlsCert == "" || tlsKey == "" {
			fmt.Println("--tls-cert and --tls-key required")
			os.Exit(1)
		}
		runWebhookServer(tlsCert, tlsKey)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Certificate for TLS")
	rootCmd.Flags().StringVar(&tlsKey, "tls-key", "", "Private key file for TLS")
	rootCmd.Flags().IntVar(&port, "port", 443, "Port to listen on for HTTPS traffic")
}

func admissionReviewFromRequest(r *http.Request, deserializer runtime.Decoder) (*admissionv1.AdmissionReview, error) {
	// Validate that the incoming content type is correct.
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("expected application/json content-type")
	}

	// Get the body data, which will be the AdmissionReview
	// content for the request.
	var body []byte
	if r.Body != nil {
		requestData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		body = requestData
	}

	// Decode the request body into
	admissionReviewRequest := &admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, admissionReviewRequest); err != nil {
		return nil, err
	}

	return admissionReviewRequest, nil
}

func validateService(w http.ResponseWriter, r *http.Request)  {
	logger.Printf("received message on validate")

	deserializer := codecs.UniversalDeserializer()

	admissionReviewRequest, err := admissionReviewFromRequest(r, deserializer)
	if err != nil {
		msg := fmt.Sprintf("error getting admission review from request: %v", err)
		logger.Printf(msg)
		w.WriteHeader(400)
		w.Write([]byte(msg))
		return
	}

	// 从admissionReview 解码service信息
	rawRequest := admissionReviewRequest.Request.Object.Raw
	service := &corev1.Service{}
	if _, _, err := deserializer.Decode(rawRequest, nil, service); err != nil {
		msg := fmt.Sprintf("error decoding raw service: %v", err)
		logger.Printf(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}


	admissionResponse := &admissionv1.AdmissionResponse{}
	admissionResponse.Allowed = true



	// 判断创建loadbalancer类型的service的slb id是否为空
	if service.Spec.Type == "LoadBalancer" && service.Annotations["service.beta.kubernetes.io/alibaba-cloud-loadbalancer-id"] == "" {
		logMsg := fmt.Sprintf("%s not specified loadbalancer id", service.Name)
		logger.Printf(logMsg)
		admissionResponse.Allowed = false
		admissionResponse.Result = &metav1.Status{
			Reason: "Create a service of loadbalancer type, you need to specify the loadbalancer id",
		}
	}


	// 判断创建loadbalancer类型的service是否带有service.beta.kubernetes.io/alibaba-cloud-loadbalancer-id
	switch service.Spec.Type {
	case "LoadBalancer":
		if _, ok := service.Annotations["service.beta.kubernetes.io/alibaba-cloud-loadbalancer-id"]; !ok {
			logMsg := fmt.Sprintf("%s not specified loadbalancer id", service.Name)
			logger.Printf(logMsg)
			admissionResponse.Allowed = false
			admissionResponse.Result = &metav1.Status{
				Reason: "Create a service of loadbalancer type, you need to specify the loadbalancer id",
			}
		}
	default:
		return
	}

	var admissionReviewResponse admissionv1.AdmissionReview
	admissionReviewResponse.Response = admissionResponse
	admissionReviewResponse.SetGroupVersionKind(admissionReviewRequest.GroupVersionKind())
	admissionReviewResponse.Response.UID = admissionReviewRequest.Request.UID

	resp, err := json.Marshal(admissionReviewResponse)
	if err != nil {
		msg := fmt.Sprintf("error marshalling response json: %v", err)
		logger.Printf(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}



func runWebhookServer(certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}

	fmt.Println("Starting webhook server")
	http.HandleFunc("/validate", validateService)
	server := http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ErrorLog: logger,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}
