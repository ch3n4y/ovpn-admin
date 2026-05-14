package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"gopkg.in/alecthomas/kingpin.v2"
)

//go:embed frontend/static
var staticFiles embed.FS

//go:embed templates
var templateFiles embed.FS

const (
	usernameRegexp         = `^([a-zA-Z0-9_.\-@])+$`
	passwordMinLength      = 6
	adminSessionCookieName = "ovpn_admin_session"
	certsArchiveFileName   = "certs.tar.gz"
	ccdArchiveFileName     = "ccd.tar.gz"
	indexTxtDateLayout     = "060102150405Z"
	stringDateFormat       = "2006-01-02 15:04:05"
	downloadCertsApiUrl    = "api/data/certs/download"
	downloadCcdApiUrl      = "api/data/ccd/download"
	labelKeyIndexTxt       = "index.txt"
	labelKeyType           = "type"
	labelKeyName           = "name"
	labelKeyManagedBy      = "app.kubernetes.io/managed-by"
	labelValueClientAuth   = "clientAuth"
	labelValueManagedByApp = "ovpn-admin"
	prefixStaticRoute      = "ifconfig-push"

	kubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	listenHost               = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort               = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
	listenBaseUrl            = kingpin.Flag("listen.base-url", "base url for ovpn-admin").Default("/").Envar("OVPN_LISTEN_BASE_URL").String()
	serverRole               = kingpin.Flag("role", "server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()
	masterHost               = kingpin.Flag("master.host", "URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterBasicAuthUser      = kingpin.Flag("master.basic-auth.user", "user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	masterBasicAuthPassword  = kingpin.Flag("master.basic-auth.password", "password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency      = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("172.16.100.0/24").Envar("OVPN_NETWORK").String()
	openvpnServer            = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	openvpnServerBehindLB    = kingpin.Flag("ovpn.server.behindLB", "enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName       = kingpin.Flag("ovpn.service", "the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").Strings()
	mgmtAddress              = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("main=127.0.0.1:8989").Envar("OVPN_MGMT").Strings()
	metricsPath              = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath           = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa").Envar("EASYRSA_PATH").String()
	indexTxtPath             = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file").Default("").Envar("OVPN_INDEX_PATH").String()
	easyrsaBinPath           = kingpin.Flag("easyrsa.bin-path", "path to easyrsa script").Default("easyrsa").Envar("EASYRSA_BIN_PATH").String()
	ccdEnabled               = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	authDataBaseInit         = kingpin.Flag("auth.db-init", "enable database initialization if db user not exists or size is 0").Default("false").Envar("OVPN_AUTH_DB_INIT").Bool()
	adminAuthEnabled         = kingpin.Flag("admin.auth", "enable admin UI authentication").Default("false").Envar("ADMIN_AUTH").Bool()
	adminAuthUser            = kingpin.Flag("admin.auth.user", "username for admin UI authentication").Default("admin").Envar("ADMIN_AUTH_USER").String()
	adminAuthPassword        = kingpin.Flag("admin.auth.password", "password for admin UI authentication").Default("").Envar("ADMIN_AUTH_PASSWORD").String()
	adminAuthTotpSecret      = kingpin.Flag("admin.auth.totp-secret", "base32 TOTP secret for admin UI authentication").Default("").Envar("ADMIN_AUTH_TOTP_SECRET").String()
	adminAuthSessionTTL      = kingpin.Flag("admin.auth.session-ttl", "session lifetime for admin UI authentication in seconds").Default("43200").Envar("ADMIN_AUTH_SESSION_TTL").Int()
	logLevel                 = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	logFormat                = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()
	storageBackend           = kingpin.Flag("storage.backend", "storage backend: filesystem, kubernetes.secrets (default filesystem)").Default("filesystem").Envar("STORAGE_BACKEND").String()
	clientCertExpirationDays = kingpin.Flag("client-cert.expiration-days", "Expiration period of OpenVPN client certificates in days, the period will shrink automatically to the CA expiration period").Default("3650").Envar("CLIENT_CERT_EXPIRATION_DAYS").String()
	crlExpirationDays        = kingpin.Flag("crl.expiration-days", "Expiration period of the generated CRL in days").Default("3650").Envar("CRL_EXPIRATION_DAYS").String()

	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName

	version = "2.0.0"
)

var logLevels = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
}

var logFormats = map[string]log.Formatter{
	"text": &log.TextFormatter{},
	"json": &log.JSONFormatter{},
}

var (
	ovpnServerCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_cert_expire",
		Help: "openvpn server certificate expire time in days",
	},
	)

	ovpnServerCaCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_ca_cert_expire",
		Help: "openvpn server CA certificate expire time in days",
	},
	)

	ovpnClientsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_total",
		Help: "total openvpn users",
	},
	)

	ovpnClientsRevoked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_revoked",
		Help: "revoked openvpn users",
	},
	)

	ovpnClientsExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_expired",
		Help: "expired openvpn users",
	},
	)

	ovpnClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_connected",
		Help: "total connected openvpn clients",
	},
	)

	ovpnUniqClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_uniq_clients_connected",
		Help: "uniq connected openvpn clients",
	},
	)

	ovpnClientCertificateExpire = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_cert_expire",
		Help: "openvpn user certificate expire time in days",
	},
		[]string{"client"},
	)

	ovpnClientConnectionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_info",
		Help: "openvpn user connection info. ip - assigned address from ovpn network. value - last time when connection was refreshed in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientConnectionFrom = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_from",
		Help: "openvpn user connection info. ip - from which address connection was initialized. value - time when connection was initialized in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientBytesReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_received",
		Help: "openvpn user bytes received",
	},
		[]string{"client"},
	)

	ovpnClientBytesSent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_sent",
		Help: "openvpn user bytes sent",
	},
		[]string{"client"},
	)
)

type OvpnAdmin struct {
	role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	clients                []OpenvpnClient
	activeClients          []clientStatus
	promRegistry           *prometheus.Registry
	mgmtInterfaces         map[string]string
	modules                []string
	mgmtStatusTimeFormat   string
	createUserMutex        *sync.Mutex
	authSessions           map[string]time.Time
	authSessionsMutex      *sync.Mutex
}

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

type openvpnClientConfig struct {
	Hosts      []OpenvpnServer
	CA         string
	Cert       string
	Key        string
	TLS        string
	PasswdAuth bool
}

type OpenvpnClient struct {
	Identity         string `json:"Identity"`
	AccountStatus    string `json:"AccountStatus"`
	ExpirationDate   string `json:"ExpirationDate"`
	RevocationDate   string `json:"RevocationDate"`
	ConnectionStatus string `json:"ConnectionStatus"`
	Connections      int    `json:"Connections"`
}

type ccdRoute struct {
	Address     string `json:"Address"`
	Mask        string `json:"Mask"`
	Description string `json:"Description"`
}

type Ccd struct {
	User          string     `json:"User"`
	ClientAddress string     `json:"ClientAddress"`
	CustomRoutes  []ccdRoute `json:"CustomRoutes"`
}

type indexTxtLine struct {
	Flag              string
	ExpirationDate    string
	RevocationDate    string
	SerialNumber      string
	Filename          string
	DistinguishedName string
	Identity          string
}

type clientStatus struct {
	CommonName              string
	RealAddress             string
	BytesReceived           string
	BytesSent               string
	ConnectedSince          string
	VirtualAddress          string
	LastRef                 string
	ConnectedSinceFormatted string
	LastRefFormatted        string
	ConnectedTo             string
}

type authStatusResponse struct {
	Enabled       bool   `json:"enabled"`
	Authenticated bool   `json:"authenticated"`
	RequiresTotp  bool   `json:"requiresTotp"`
	Username      string `json:"username"`
}

type authLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

func adminAuthRequiresTOTP() bool {
	return strings.TrimSpace(*adminAuthTotpSecret) != ""
}

func generateSessionToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func normalizeTOTPSecret(secret string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	return strings.ReplaceAll(normalized, "-", "")
}

func verifyTOTPCode(secret, code string, now time.Time) bool {
	secret = normalizeTOTPSecret(secret)
	if secret == "" {
		return true
	}

	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		log.Warnf("invalid admin TOTP secret: %v", err)
		return false
	}

	timeStep := now.Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		counter := uint64(timeStep + offset)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], counter)

		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(buf[:])
		sum := mac.Sum(nil)
		pos := sum[len(sum)-1] & 0x0f
		truncated := binary.BigEndian.Uint32(sum[pos:pos+4]) & 0x7fffffff
		expected := fmt.Sprintf("%06d", truncated%1000000)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}

	return false
}

func (oAdmin *OvpnAdmin) cleanupExpiredSessions(now time.Time) {
	oAdmin.authSessionsMutex.Lock()
	defer oAdmin.authSessionsMutex.Unlock()

	for token, expiry := range oAdmin.authSessions {
		if now.After(expiry) {
			delete(oAdmin.authSessions, token)
		}
	}
}

func (oAdmin *OvpnAdmin) isAuthenticated(r *http.Request) bool {
	if !*adminAuthEnabled {
		return true
	}

	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	now := time.Now()
	oAdmin.cleanupExpiredSessions(now)

	oAdmin.authSessionsMutex.Lock()
	defer oAdmin.authSessionsMutex.Unlock()

	expiry, ok := oAdmin.authSessions[cookie.Value]
	if !ok || now.After(expiry) {
		delete(oAdmin.authSessions, cookie.Value)
		return false
	}

	oAdmin.authSessions[cookie.Value] = now.Add(time.Duration(*adminAuthSessionTTL) * time.Second)
	return true
}

func (oAdmin *OvpnAdmin) setAuthCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   false,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

func (oAdmin *OvpnAdmin) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   false,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (oAdmin *OvpnAdmin) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !oAdmin.isAuthenticated(r) {
			http.Error(w, `{"status":"error","message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (oAdmin *OvpnAdmin) authStatusHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	status := authStatusResponse{
		Enabled:       *adminAuthEnabled,
		Authenticated: oAdmin.isAuthenticated(r),
		RequiresTotp:  adminAuthRequiresTOTP(),
	}
	if status.Authenticated {
		status.Username = *adminAuthUser
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (oAdmin *OvpnAdmin) authLoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if !*adminAuthEnabled {
		http.Error(w, `{"status":"error","message":"admin auth disabled"}`, http.StatusBadRequest)
		return
	}

	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"status":"error","message":"invalid request"}`, http.StatusBadRequest)
		return
	}

	userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(*adminAuthUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(req.Password), []byte(*adminAuthPassword)) == 1
	totpOK := verifyTOTPCode(*adminAuthTotpSecret, req.TOTP, time.Now())

	if !userOK || !passOK || !totpOK {
		http.Error(w, `{"status":"error","message":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, err := generateSessionToken()
	if err != nil {
		http.Error(w, `{"status":"error","message":"failed to create session"}`, http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(time.Duration(*adminAuthSessionTTL) * time.Second)
	oAdmin.authSessionsMutex.Lock()
	oAdmin.authSessions[token] = expiresAt
	oAdmin.authSessionsMutex.Unlock()
	oAdmin.setAuthCookie(w, token, expiresAt)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authStatusResponse{
		Enabled:       true,
		Authenticated: true,
		RequiresTotp:  adminAuthRequiresTOTP(),
		Username:      *adminAuthUser,
	})
}

func (oAdmin *OvpnAdmin) authLogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if cookie, err := r.Cookie(adminSessionCookieName); err == nil && cookie.Value != "" {
		oAdmin.authSessionsMutex.Lock()
		delete(oAdmin.authSessions, cookie.Value)
		oAdmin.authSessionsMutex.Unlock()
	}
	oAdmin.clearAuthCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	if *storageBackend == "kubernetes.secrets" {
		err := app.updateIndexTxtOnDisk()
		if err != nil {
			log.Errorln(err)
		}
		oAdmin.clients = oAdmin.usersList()
	}

	usersList, _ := json.Marshal(oAdmin.clients)
	fmt.Fprintf(w, "%s", usersList)
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprintf(w, "%s", userStatistic)
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	userCreated, userCreateStatus := oAdmin.userCreate(r.FormValue("username"), r.FormValue("password"))

	if userCreated {
		oAdmin.clients = oAdmin.usersList()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, userCreateStatus)
		return
	} else {
		http.Error(w, userCreateStatus, http.StatusUnprocessableEntity)
	}
}
func (oAdmin *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRotate(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userDelete(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userUnrevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	if *authByPassword {
		err, msg := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"status":"error", "message": "%s"}`, msg)

		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok", "message": "%s"}`, msg)
		}
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(r.FormValue("username"), requestHost(r)))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	ccd, _ := json.Marshal(oAdmin.getCcd(r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var ccd Ccd
	if r.Body == nil {
		http.Error(w, "Please send a request body", http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		log.Errorln(err)
	}

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)

	if ccdApplied {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, applyStatus)
		return
	} else {
		http.Error(w, applyStatus, http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enabledModules, enabledModulesErr := json.Marshal(oAdmin.modules)
	if enabledModulesErr != nil {
		log.Errorln(enabledModulesErr)
	}
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.role, string(enabledModules))
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.lastSyncTime)
}

func (oAdmin *OvpnAdmin) lastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.lastSuccessfulSyncTime)
}

func (oAdmin *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (oAdmin *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

var app OpenVPNPKI

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	log.SetLevel(logLevels[*logLevel])
	log.SetFormatter(logFormats[*logFormat])

	if *storageBackend == "kubernetes.secrets" {
		err := app.run()
		if err != nil {
			log.Error(err)
		}
	}

	if *indexTxtPath == "" {
		*indexTxtPath = *easyrsaDirPath + "/pki/index.txt"
	}

	if *authDataBaseInit {
		ovpnUserInitDb()
	}

	ovpnAdmin := new(OvpnAdmin)

	ovpnAdmin.lastSyncTime = "unknown"
	ovpnAdmin.role = *serverRole
	ovpnAdmin.lastSuccessfulSyncTime = "unknown"
	ovpnAdmin.masterSyncToken = *masterSyncToken
	ovpnAdmin.promRegistry = prometheus.NewRegistry()
	ovpnAdmin.modules = []string{}
	ovpnAdmin.createUserMutex = &sync.Mutex{}
	ovpnAdmin.authSessions = make(map[string]time.Time)
	ovpnAdmin.authSessionsMutex = &sync.Mutex{}
	ovpnAdmin.mgmtInterfaces = make(map[string]string)

	if *adminAuthEnabled && *adminAuthPassword == "" {
		log.Fatal("admin auth is enabled but ADMIN_AUTH_PASSWORD is empty")
	}

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	ovpnAdmin.mgmtSetTimeFormat()

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()

	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		ovpnAdmin.masterHostBasicAuth = true
	} else {
		ovpnAdmin.masterHostBasicAuth = false
	}

	ovpnAdmin.modules = append(ovpnAdmin.modules, "core")

	if *authByPassword {
		if *storageBackend != "kubernetes.secrets" {
			ovpnAdmin.modules = append(ovpnAdmin.modules, "passwdAuth")
		} else {
			log.Fatal("Right now the keys `--storage.backend=kubernetes.secret` and `--auth.password` are not working together. Please use only one of them ")
		}
	}

	if *ccdEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ccd")
	}

	if ovpnAdmin.role == "slave" {
		ovpnAdmin.syncDataFromMaster()
		go ovpnAdmin.syncWithMaster()
	}

	staticFS, _ := fs.Sub(staticFiles, "frontend/static")
	static := CacheControlWrapper(http.FileServer(http.FS(staticFS)))

	http.Handle(*listenBaseUrl, http.StripPrefix(strings.TrimRight(*listenBaseUrl, "/"), static))
	http.HandleFunc(*listenBaseUrl+"api/auth/status", ovpnAdmin.authStatusHandler)
	http.HandleFunc(*listenBaseUrl+"api/auth/login", ovpnAdmin.authLoginHandler)
	http.HandleFunc(*listenBaseUrl+"api/auth/logout", ovpnAdmin.authLogoutHandler)
	http.HandleFunc(*listenBaseUrl+"api/server/settings", ovpnAdmin.requireAdminAuth(ovpnAdmin.serverSettingsHandler))
	http.HandleFunc(*listenBaseUrl+"api/users/list", ovpnAdmin.requireAdminAuth(ovpnAdmin.userListHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/create", ovpnAdmin.requireAdminAuth(ovpnAdmin.userCreateHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/change-password", ovpnAdmin.requireAdminAuth(ovpnAdmin.userChangePasswordHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/rotate", ovpnAdmin.requireAdminAuth(ovpnAdmin.userRotateHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/delete", ovpnAdmin.requireAdminAuth(ovpnAdmin.userDeleteHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/revoke", ovpnAdmin.requireAdminAuth(ovpnAdmin.userRevokeHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/unrevoke", ovpnAdmin.requireAdminAuth(ovpnAdmin.userUnrevokeHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/config/show", ovpnAdmin.requireAdminAuth(ovpnAdmin.userShowConfigHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/disconnect", ovpnAdmin.requireAdminAuth(ovpnAdmin.userDisconnectHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/statistic", ovpnAdmin.requireAdminAuth(ovpnAdmin.userStatisticHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/ccd", ovpnAdmin.requireAdminAuth(ovpnAdmin.userShowCcdHandler))
	http.HandleFunc(*listenBaseUrl+"api/user/ccd/apply", ovpnAdmin.requireAdminAuth(ovpnAdmin.userApplyCcdHandler))

	http.HandleFunc(*listenBaseUrl+"api/sync/last/try", ovpnAdmin.requireAdminAuth(ovpnAdmin.lastSyncTimeHandler))
	http.HandleFunc(*listenBaseUrl+"api/sync/last/successful", ovpnAdmin.requireAdminAuth(ovpnAdmin.lastSuccessfulSyncTimeHandler))
	http.HandleFunc(*listenBaseUrl+downloadCertsApiUrl, ovpnAdmin.downloadCertsHandler)
	http.HandleFunc(*listenBaseUrl+downloadCcdApiUrl, ovpnAdmin.downloadCcdHandler)

	http.Handle(*metricsPath, promhttp.HandlerFor(ovpnAdmin.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc(*listenBaseUrl+"ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})

	log.Printf("Bind: http://%s:%s%s", *listenHost, *listenPort, *listenBaseUrl)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, nil))
}

func CacheControlWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
		h.ServeHTTP(w, r)
	})
}

func (oAdmin *OvpnAdmin) registerMetrics() {
	oAdmin.promRegistry.MustRegister(ovpnServerCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnServerCaCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientsTotal)
	oAdmin.promRegistry.MustRegister(ovpnClientsRevoked)
	oAdmin.promRegistry.MustRegister(ovpnClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnUniqClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnClientsExpired)
	oAdmin.promRegistry.MustRegister(ovpnClientCertificateExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionInfo)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionFrom)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesReceived)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesSent)
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.activeClients = oAdmin.mgmtGetActiveClients()
	oAdmin.clients = oAdmin.usersList()

	ovpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
}

func (oAdmin *OvpnAdmin) updateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		ovpnClientBytesSent.Reset()
		ovpnClientBytesReceived.Reset()
		ovpnClientConnectionFrom.Reset()
		ovpnClientConnectionInfo.Reset()
		ovpnClientCertificateExpire.Reset()
		go oAdmin.setState()
	}
}

func indexTxtParser(txt string) []indexTxtLine {
	var indexTxt []indexTxtLine

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "E"), strings.HasPrefix(str[0], "V"):
				if len(str) < 5 {
					log.Warnf("skip malformed index.txt line: %q", v)
					continue
				}
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], SerialNumber: str[2], Filename: str[3], DistinguishedName: str[4], Identity: extractIdentity(str[4])})
			case strings.HasPrefix(str[0], "R"):
				if len(str) < 6 {
					log.Warnf("skip malformed revoked index.txt line: %q", v)
					continue
				}
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], RevocationDate: str[2], SerialNumber: str[3], Filename: str[4], DistinguishedName: str[5], Identity: extractIdentity(str[5])})
			}
		}
	}

	return indexTxt
}

func extractIdentity(distinguishedName string) string {
	if idx := strings.Index(distinguishedName, "="); idx >= 0 && idx < len(distinguishedName)-1 {
		return distinguishedName[idx+1:]
	}
	return distinguishedName
}

func renderIndexTxt(data []indexTxtLine) string {
	indexTxt := ""
	for _, line := range data {
		switch {
		case line.Flag == "V", line.Flag == "E":
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		case line.Flag == "R":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		}
	}
	return indexTxt
}

func (oAdmin *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTplBytes, clientConfigTplErr := templateFiles.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Errorf("clientConfigTpl not found in embedded templates: %v", clientConfigTplErr)
		}
		return template.Must(template.New("client-config").Parse(string(clientConfigTplBytes)))
	}
}

func requestHost(r *http.Request) string {
	if forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		return strings.Split(forwardedHost, ",")[0]
	}
	return r.Host
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "", "127.0.0.1", "localhost", "0.0.0.0", "::1":
		return true
	default:
		return false
	}
}

func normalizeOpenVPNHosts(servers []string, requestHost string) []OpenvpnServer {
	var hosts []OpenvpnServer
	requestHostName := strings.TrimSpace(requestHost)
	if parsedHost, _, err := net.SplitHostPort(requestHost); err == nil {
		requestHostName = parsedHost
	}

	for _, server := range servers {
		parts := strings.SplitN(server, ":", 3)
		if len(parts) != 3 {
			log.Warnf("skip invalid OVPN_SERVER entry %q", server)
			continue
		}

		host := strings.TrimSpace(parts[0])
		if isLoopbackHost(host) && requestHostName != "" {
			host = requestHostName
		}

		hosts = append(hosts, OpenvpnServer{
			Host:     host,
			Port:     strings.TrimSpace(parts[1]),
			Protocol: strings.TrimSpace(parts[2]),
		})
	}

	return hosts
}

func (oAdmin *OvpnAdmin) renderClientConfig(username, requestHost string) string {
	if checkUserExist(username) {
		hosts := normalizeOpenVPNHosts(*openvpnServer, requestHost)

		if *openvpnServerBehindLB {
			var err error
			hosts, err = getOvpnServerHostsFromKubeApi()
			if err != nil {
				log.Error(err)
			}
		}

		log.Tracef("hosts for %s\n %v", username, hosts)

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
		conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")

		if *storageBackend == "kubernetes.secrets" {
			conf.Cert, conf.Key = app.easyrsaGetClientCert(username)
		} else {
			conf.Cert = fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt")
			conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")
		}

		conf.PasswdAuth = *authByPassword

		t := oAdmin.getClientConfigTemplate()

		var tmp bytes.Buffer
		err := t.Execute(&tmp, conf)
		if err != nil {
			log.Errorf("something goes wrong during rendering config for %s", username)
			log.Debugf("rendering config for %s failed with error %v", username, err)
		}

		hosts = nil

		log.Tracef("Rendered config for user %s: %+v", username, tmp.String())

		return fmt.Sprintf("%+v", tmp.String())
	}
	log.Warnf("user \"%s\" not found", username)
	return fmt.Sprintf("user \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) getCcdTemplate() *template.Template {
	if *ccdTemplatePath != "" {
		return template.Must(template.ParseFiles(*ccdTemplatePath))
	} else {
		ccdTplBytes, ccdTplErr := templateFiles.ReadFile("templates/ccd.tpl")
		if ccdTplErr != nil {
			log.Errorf("ccdTpl not found in embedded templates: %v", ccdTplErr)
		}
		return template.Must(template.New("ccd").Parse(string(ccdTplBytes)))
	}
}

func (oAdmin *OvpnAdmin) parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	var txtLinesArray []string
	if *storageBackend == "kubernetes.secrets" {
		txtLinesArray = strings.Split(app.secretGetCcd(ccd.User), "\n")
	} else {
		ccdPath, err := ccdFilePath(username)
		if err != nil {
			log.Warn(err)
			return ccd
		}
		if fExist(ccdPath) {
			txtLinesArray = strings.Split(fRead(ccdPath), "\n")
		}
	}

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "ifconfig-push"):
				ccd.ClientAddress = str[1]
			case strings.HasPrefix(str[0], "push"):
				ccd.CustomRoutes = append(ccd.CustomRoutes, ccdRoute{Address: strings.Trim(str[2], "\""), Mask: strings.Trim(str[3], "\""), Description: strings.Trim(strings.Join(str[4:], ""), "#")})
			}
		}
	}

	return ccd
}

func (oAdmin *OvpnAdmin) modifyCcd(ccd Ccd) (bool, string) {
	ccdValid, err := validateCcd(ccd)
	if err != "" {
		return false, err
	}

	if ccdValid {
		t := oAdmin.getCcdTemplate()
		var tmp bytes.Buffer
		err := t.Execute(&tmp, ccd)
		if err != nil {
			log.Error(err)
		}
		if *storageBackend == "kubernetes.secrets" {
			app.secretUpdateCcd(ccd.User, tmp.Bytes())
		} else {
			ccdPath, pathErr := ccdFilePath(ccd.User)
			if pathErr != nil {
				return false, pathErr.Error()
			}
			err = fWrite(ccdPath, tmp.String())
			if err != nil {
				log.Errorf("modifyCcd: fWrite(): %v", err)
			}
		}

		return true, "ccd updated successfully"
	}

	return false, "something goes wrong"
}

func validateCcd(ccd Ccd) (bool, string) {

	ccdErr := ""

	if ccd.ClientAddress != "dynamic" {
		_, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			log.Error(err)
		}

		if !checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(ccd.ClientAddress) == nil {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if !ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	for _, route := range ccd.CustomRoutes {
		if net.ParseIP(route.Address) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(route.Mask) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Mask)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	return true, ccdErr
}

func (oAdmin *OvpnAdmin) getCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	ccd = oAdmin.parseCcd(username)

	return ccd
}

func checkStaticAddressIsFree(staticAddress string, username string) bool {

	if *storageBackend == "kubernetes.secrets" {

		log.Infof("Static address: %s", staticAddress)

		labelSelector := fmt.Sprintf("%s=%s,%s=%s",
			labelKeyType, labelValueClientAuth,
			labelKeyManagedBy, labelValueManagedByApp)

		secrets, err := app.secretsGetByLabels(labelSelector)
		if err != nil {
			log.Error(err)
		}

		for _, secret := range secrets.Items {
			otherUser := secret.Labels["name"]
			if otherUser == username {
				continue
			}

			dataCCD, ok := secret.Data["ccd"]
			if !ok {
				continue
			}

			lines := strings.Split(string(dataCCD), "\n")

			for _, line := range lines {
				if strings.HasPrefix(line, prefixStaticRoute) {
					fields := strings.Fields(line)
					if len(fields) >= 2 && fields[1] == staticAddress {
						log.Warnf("IP %s already assigned to user %s", staticAddress, otherUser)
						return false
					}
				}
			}
		}

		return true
	}

	entries, err := os.ReadDir(*ccdDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		log.Warn(err)
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == username {
			continue
		}
		ccdPath, pathErr := ccdFilePath(entry.Name())
		if pathErr != nil {
			log.Warn(pathErr)
			continue
		}
		for _, line := range strings.Split(fRead(ccdPath), "\n") {
			if strings.HasPrefix(line, prefixStaticRoute) {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] == staticAddress {
					return false
				}
			}
		}
	}

	return true
}

func validateUsername(username string) error {
	var validUsername = regexp.MustCompile(usernameRegexp)
	if validUsername.MatchString(username) {
		return nil
	} else {
		return errors.New(fmt.Sprintf("Username can only contains %s", usernameRegexp))
	}
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < passwordMinLength {
		return errors.New(fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength))
	} else {
		return nil
	}
}

func ccdFilePath(username string) (string, error) {
	if err := validateUsername(username); err != nil {
		return "", err
	}
	return safeJoin(*ccdDir, username)
}

func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + username) {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users []OpenvpnClient

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if line.Identity != "server" && !strings.Contains(line.Identity, "REVOKED") {
			totalCerts += 1
			ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: parseDateToString(indexTxtDateLayout, line.ExpirationDate, stringDateFormat)}
			switch {
			case line.Flag == "V":
				ovpnClient.AccountStatus = "Active"
				validCerts += 1
			case line.Flag == "R":
				ovpnClient.AccountStatus = "Revoked"
				ovpnClient.RevocationDate = parseDateToString(indexTxtDateLayout, line.RevocationDate, stringDateFormat)
				revokedCerts += 1
			case line.Flag == "E":
				ovpnClient.AccountStatus = "Expired"
				expiredCerts += 1
			}

			ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))

			if (parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) < 0 {
				if ovpnClient.AccountStatus != "Revoked" {
					ovpnClient.AccountStatus = "Expired"
				}
			}
			ovpnClient.Connections = 0

			userConnected, userConnectedTo := isUserConnected(line.Identity, oAdmin.activeClients)
			if userConnected {
				ovpnClient.ConnectionStatus = "Connected"
				for range userConnectedTo {
					ovpnClient.Connections += 1
					totalActiveConnections += 1
				}
				connectedUniqUsers += 1
			}

			users = append(users, ovpnClient)

		} else {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))

	return users
}

func (oAdmin *OvpnAdmin) userCreate(username, password string) (bool, string) {
	ucErr := fmt.Sprintf("User \"%s\" created", username)

	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if checkUserExist(username) {
		ucErr = fmt.Sprintf("User \"%s\" already exists\n", username)
		log.Debugf("userCreate: checkUserExist():  %s", ucErr)
		return false, ucErr
	}

	if err := validateUsername(username); err != nil {
		log.Debugf("userCreate: validateUsername(): %s", err.Error())
		return false, err.Error()
	}

	if *authByPassword {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: authByPassword(): %s", err.Error())
			return false, err.Error()
		}
	}

	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaBuildClient(username)
		if err != nil {
			log.Error(err)
			return false, err.Error()
		}
	} else {
		o := runBash(fmt.Sprintf("cd %s && %s --batch build-client-full %s nopass 1>/dev/null",
			shellQuote(*easyrsaDirPath), shellQuote(*easyrsaBinPath), shellQuote(username)))
		log.Debug(o)
	}

	if *authByPassword {
		o := runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s",
			shellQuote(*authDatabase), shellQuote(username), shellQuote(password)))
		log.Debug(o)
	}

	log.Infof("Certificate for user %s issued", username)

	//oAdmin.clients = oAdmin.usersList()

	return true, ucErr
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (error, string) {

	if checkUserExist(username) {
		o := runBash(fmt.Sprintf("openvpn-user check --db.path %s --user %s | grep -F %s | wc -l",
			shellQuote(*authDatabase), shellQuote(username), shellQuote(username)))
		log.Debug(o)

		if err := validatePassword(password); err != nil {
			log.Warningf("userChangePassword: %s", err.Error())
			return err, err.Error()
		}

		if strings.TrimSpace(o) == "0" {
			o = runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s",
				shellQuote(*authDatabase), shellQuote(username), shellQuote(password)))
			log.Debug(o)
		}

		o = runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s",
			shellQuote(*authDatabase), shellQuote(username), shellQuote(password)))
		log.Debug(o)

		log.Infof("Password for user %s was changed", username)

		return nil, "Password changed"
	}

	return errors.New(fmt.Sprintf("User \"%s\" not found}", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []clientStatus {
	var userStatistic []clientStatus
	for _, u := range oAdmin.activeClients {
		if u.CommonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
}

func (oAdmin *OvpnAdmin) userRevoke(username string) (error, string) {
	log.Infof("Revoke certificate for user %s", username)
	if checkUserExist(username) {
		// check certificate valid flag 'V'
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaRevoke(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			o := runBash(fmt.Sprintf("cd %s && echo yes | %s revoke %s 1>/dev/null && %s gen-crl 1>/dev/null",
				shellQuote(*easyrsaDirPath), shellQuote(*easyrsaBinPath), shellQuote(username), shellQuote(*easyrsaBinPath)))
			log.Debugln(o)
		}

		if *authByPassword {
			o := runBash(fmt.Sprintf("openvpn-user revoke --db.path %s --user %s",
				shellQuote(*authDatabase), shellQuote(username)))
			log.Debug(o)
		}

		crlFix()
		userConnected, userConnectedTo := isUserConnected(username, oAdmin.activeClients)
		log.Tracef("User %s connected: %t", username, userConnected)
		if userConnected {
			for _, connection := range userConnectedTo {
				oAdmin.mgmtKillUserConnection(username, connection)
				log.Infof("Session for user \"%s\" killed", username)
			}
		}

		oAdmin.setState()
		return nil, fmt.Sprintf("user \"%s\" revoked", username)
	}
	log.Infof("user \"%s\" not found", username)
	return errors.New(fmt.Sprintf("User \"%s\" not found}", username)), fmt.Sprintf("User \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) (error, string) {
	if checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaUnrevoke(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			// check certificate revoked flag 'R'
			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					if usersFromIndexTxt[i].Flag == "R" {

						usersFromIndexTxt[i].Flag = "V"
						usersFromIndexTxt[i].RevocationDate = ""

						err := fMove(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/issued/%s.crt", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/certs_by_serial/%s.pem", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/private/%s.key", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/reqs_by_serial/%s.req", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/reqs/%s.req", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
						if err != nil {
							log.Error(err)
						}

						_ = runBash(fmt.Sprintf("cd %s && %s gen-crl 1>/dev/null",
							shellQuote(*easyrsaDirPath), shellQuote(*easyrsaBinPath)))

						if *authByPassword {
							o := runBash(fmt.Sprintf("openvpn-user restore --db.path %s --user %s",
								shellQuote(*authDatabase), shellQuote(username)))
							log.Debug(o)
						}

						crlFix()

						break
					}
				}
			}
			err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}
			//fmt.Print(renderIndexTxt(usersFromIndexTxt))
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
	}
	return errors.New(fmt.Sprintf("user \"%s\" not found", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) userRotate(username, newPassword string) (error, string) {
	if checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaRotate(username, newPassword)
			if err != nil {
				log.Error(err)
			}
		} else {

			var oldUserIndex, newUserIndex int
			var oldUserSerial string

			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)

			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					oldUserSerial = usersFromIndexTxt[i].SerialNumber
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					oldUserIndex = i
					break
				}
			}
			err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}

			if *authByPassword {
				o := runBash(fmt.Sprintf("openvpn-user delete --force --db.path %s --user %s",
					shellQuote(*authDatabase), shellQuote(username)))
				log.Debug(o)
			}

			userCreated, userCreateMessage := oAdmin.userCreate(username, newPassword)
			if !userCreated {
				usersFromIndexTxt = indexTxtParser(fRead(*indexTxtPath))
				for i := range usersFromIndexTxt {
					if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
						usersFromIndexTxt[i].DistinguishedName = "/CN=" + username
						break
					}
				}
				err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
				if err != nil {
					log.Error(err)
				}
				return errors.New(fmt.Sprintf("error rotaing user due:  %s", userCreateMessage)), userCreateMessage
			}

			usersFromIndexTxt = indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					newUserIndex = i
				}
				if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
					oldUserIndex = i
				}
			}
			usersFromIndexTxt[oldUserIndex], usersFromIndexTxt[newUserIndex] = usersFromIndexTxt[newUserIndex], usersFromIndexTxt[oldUserIndex]

			err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}

			_ = runBash(fmt.Sprintf("cd %s && %s gen-crl 1>/dev/null",
				shellQuote(*easyrsaDirPath), shellQuote(*easyrsaBinPath)))
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully rotated\"}", username)
	}
	return errors.New(fmt.Sprintf("user \"%s\" not found", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) userDelete(username string) (error, string) {
	if checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaDelete(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					break
				}
			}
			if *authByPassword {
				_ = runBash(fmt.Sprintf("openvpn-user delete --force --db.path %s --user %s",
					shellQuote(*authDatabase), shellQuote(username)))
			}
			err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}
			_ = runBash(fmt.Sprintf("cd %s && %s gen-crl 1>/dev/null",
				shellQuote(*easyrsaDirPath), shellQuote(*easyrsaBinPath)))
		}
		crlFix()
		if *storageBackend != "kubernetes.secrets" {
			ccdPath, err := ccdFilePath(username)
			if err != nil {
				log.Warn(err)
			} else if fExist(ccdPath) {
				if err := fDelete(ccdPath); err != nil {
					log.Warn(err)
				}
			}
		}
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully deleted\"}", username)
	}
	return errors.New(fmt.Sprintf("User \"%s\" not found}", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) mgmtRead(conn net.Conn) string {
	recvData := make([]byte, 32768)
	var out string
	var n int
	var err error
	for {
		n, err = conn.Read(recvData)
		if n <= 0 || err != nil {
			break
		} else {
			out += string(recvData[:n])
			if strings.Contains(out, "type 'help' for more info") || strings.Contains(out, "END") || strings.Contains(out, "SUCCESS:") || strings.Contains(out, "ERROR:") {
				break
			}
		}
	}
	return out
}

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser(text, serverName string) []clientStatus {
	var u []clientStatus
	isClientList := false
	isRouteTable := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		txt := scanner.Text()
		if regexp.MustCompile(`^Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since$`).MatchString(txt) {
			isClientList = true
			continue
		}
		if regexp.MustCompile(`^ROUTING TABLE$`).MatchString(txt) {
			isClientList = false
			continue
		}
		if regexp.MustCompile(`^Virtual Address,Common Name,Real Address,Last Ref$`).MatchString(txt) {
			isRouteTable = true
			continue
		}
		if regexp.MustCompile(`^GLOBAL STATS$`).MatchString(txt) {
			// isRouteTable = false // ineffectual assignment to isRouteTable (ineffassign)
			break
		}
		if isClientList {
			user := strings.Split(txt, ",")
			if len(user) < 5 {
				log.Warnf("skip malformed client list line: %q", txt)
				continue
			}

			userName := user[0]
			userAddress := user[1]
			userBytesReceived := user[2]
			userBytesSent := user[3]
			userConnectedSince := user[4]

			userStatus := clientStatus{CommonName: userName, RealAddress: userAddress, BytesReceived: userBytesReceived, BytesSent: userBytesSent, ConnectedSince: userConnectedSince, ConnectedTo: serverName}
			u = append(u, userStatus)
			bytesSent, _ := strconv.Atoi(userBytesSent)
			bytesReceive, _ := strconv.Atoi(userBytesReceived)
			ovpnClientConnectionFrom.WithLabelValues(userName, userAddress).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, userConnectedSince)))
			ovpnClientBytesSent.WithLabelValues(userName).Set(float64(bytesSent))
			ovpnClientBytesReceived.WithLabelValues(userName).Set(float64(bytesReceive))
		}
		if isRouteTable {
			user := strings.Split(txt, ",")
			if len(user) < 4 {
				log.Warnf("skip malformed route table line: %q", txt)
				continue
			}
			for i := range u {
				if u[i].CommonName == user[1] {
					u[i].VirtualAddress = user[0]
					u[i].LastRef = user[3]
					ovpnClientConnectionInfo.WithLabelValues(user[1], user[0]).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(username, serverName string) {
	conn, err := net.Dial("tcp", oAdmin.mgmtInterfaces[serverName])
	if err != nil {
		log.Errorf("openvpn mgmt interface for %s is not reachable by addr %s", serverName, oAdmin.mgmtInterfaces[serverName])
		return
	}
	oAdmin.mgmtRead(conn) // read welcome message
	conn.Write([]byte(fmt.Sprintf("kill %s\n", username)))
	fmt.Printf("%v", oAdmin.mgmtRead(conn))
	conn.Close()
}

func (oAdmin *OvpnAdmin) mgmtGetActiveClients() []clientStatus {
	var activeClients []clientStatus

	for srv, addr := range oAdmin.mgmtInterfaces {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Warnf("openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			continue
		}
		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("status 1\n"))
		activeClients = append(activeClients, oAdmin.mgmtConnectedUsersParser(oAdmin.mgmtRead(conn), srv)...)
		conn.Close()
	}
	return activeClients
}

func (oAdmin *OvpnAdmin) mgmtSetTimeFormat() {
	// time format for version 2.5 and may be newer
	oAdmin.mgmtStatusTimeFormat = "2006-01-02 15:04:05"
	log.Debugf("mgmtStatusTimeFormat: %s", oAdmin.mgmtStatusTimeFormat)

	type serverVersion struct {
		name    string
		version string
	}

	var serverVersions []serverVersion

	for srv, addr := range oAdmin.mgmtInterfaces {

		var conn net.Conn
		var err error
		for connAttempt := 0; connAttempt < 10; connAttempt++ {
			conn, err = net.Dial("tcp", addr)
			if err == nil {
				log.Debugf("mgmtSetTimeFormat: successful connection to %s/%s", srv, addr)
				break
			}
			log.Warnf("mgmtSetTimeFormat: openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			time.Sleep(time.Duration(2) * time.Second)
		}
		if err != nil {
			break
		}

		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("version\n"))
		out := oAdmin.mgmtRead(conn)
		conn.Close()

		log.Trace(out)

		for _, s := range strings.Split(out, "\n") {
			if strings.Contains(s, "OpenVPN Version:") {
				fields := strings.Fields(s)
				if len(fields) >= 4 {
					serverVersions = append(serverVersions, serverVersion{srv, fields[3]})
				} else {
					log.Warnf("mgmtSetTimeFormat: unexpected version output for %s: %q", srv, s)
				}
				break
			}
		}
	}

	if len(serverVersions) == 0 {
		return
	}

	firstVersion := serverVersions[0].version

	if strings.HasPrefix(firstVersion, "2.4") {
		oAdmin.mgmtStatusTimeFormat = time.ANSIC
		log.Debugf("mgmtStatusTimeFormat changed: %s", oAdmin.mgmtStatusTimeFormat)
	}

	warn := ""
	for _, v := range serverVersions {
		if firstVersion != v.version {
			warn = "mgmtSetTimeFormat: servers have different versions of openvpn, user connection status may not work"
			log.Warn(warn)
			break
		}
	}

	if warn != "" {
		for _, v := range serverVersions {
			log.Infof("server name: %s, version: %s", v.name, v.version)
		}
	}
}

func isUserConnected(username string, connectedUsers []clientStatus) (bool, []string) {
	var connections []string
	var connected = false

	for _, connectedUser := range connectedUsers {
		if connectedUser.CommonName == username {
			connected = true
			connections = append(connections, connectedUser.ConnectedTo)
		}
	}
	return connected, connections
}

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+*listenBaseUrl+downloadCertsApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+*listenBaseUrl+downloadCcdApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func archiveCerts() {
	err := createArchiveFromDir(*easyrsaDirPath+"/pki", certsArchivePath)
	if err != nil {
		log.Warnf("archiveCerts(): %s", err)
	}
}

func archiveCcd() {
	err := createArchiveFromDir(*ccdDir, ccdArchivePath)
	if err != nil {
		log.Warnf("archiveCcd(): %s", err)
	}
}

func unArchiveCerts() {
	if err := os.MkdirAll(*easyrsaDirPath+"/pki", 0755); err != nil {
		log.Warnf("unArchiveCerts(): error creating pki dir: %s", err)
	}

	err := extractFromArchive(certsArchivePath, *easyrsaDirPath+"/pki")
	if err != nil {
		log.Warnf("unArchiveCerts: extractFromArchive() %s", err)
	}
}

func unArchiveCcd() {
	if err := os.MkdirAll(*ccdDir, 0755); err != nil {
		log.Warnf("unArchiveCcd(): error creating ccd dir: %s", err)
	}

	err := extractFromArchive(ccdArchivePath, *ccdDir)
	if err != nil {
		log.Warnf("unArchiveCcd: extractFromArchive() %s", err)
	}
}

func ovpnUserInitDb() {
	if fi, err := os.Stat(*authDatabase); errors.Is(err, os.ErrNotExist) || fi.Size() == 0 {
		i := runBash(fmt.Sprintf("openvpn-user --db.path %s db-init && openvpn-user --db.path %s db-migrate",
			shellQuote(*authDatabase), shellQuote(*authDatabase)))
		log.Debug(i)
	}
}

func (oAdmin *OvpnAdmin) syncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true

	for certsDownloadRetries := 0; certsDownloadRetries < retryCountMax; certsDownloadRetries++ {
		log.Infof("Downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		if oAdmin.downloadCerts() {
			certsDownloadFailed = false
			log.Info("Decompressing archive with certificates from master")
			unArchiveCerts()
			log.Info("Decompression archive with certificates from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		}
	}

	for ccdDownloadRetries := 0; ccdDownloadRetries < retryCountMax; ccdDownloadRetries++ {
		log.Infof("Downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		if oAdmin.downloadCcd() {
			ccdDownloadFailed = false
			log.Info("Decompressing archive with ccd from master")
			unArchiveCcd()
			log.Info("Decompression archive with ccd from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		}
	}

	oAdmin.lastSyncTime = time.Now().Format(stringDateFormat)
	if !ccdDownloadFailed && !certsDownloadFailed {
		oAdmin.lastSuccessfulSyncTime = time.Now().Format(stringDateFormat)
	}
}

func (oAdmin *OvpnAdmin) syncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.syncDataFromMaster()
	}
}

func getOvpnServerHostsFromKubeApi() ([]OpenvpnServer, error) {
	var hosts []OpenvpnServer
	var lbHost string

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	for _, serviceName := range *openvpnServiceName {
		service, err := clientset.CoreV1().Services(fRead(kubeNamespaceFilePath)).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			log.Error(err)
		}

		log.Tracef("service from kube api %v", service)
		log.Tracef("service.Status from kube api %v", service.Status)
		log.Tracef("service.Status.LoadBalancer from kube api %v", service.Status.LoadBalancer)

		lbIngress := service.Status.LoadBalancer.Ingress
		if len(lbIngress) > 0 {
			if lbIngress[0].Hostname != "" {
				lbHost = lbIngress[0].Hostname
			}

			if lbIngress[0].IP != "" {
				lbHost = lbIngress[0].IP
			}
		}

		hosts = append(hosts, OpenvpnServer{lbHost, strconv.Itoa(int(service.Spec.Ports[0].Port)), strings.ToLower(string(service.Spec.Ports[0].Protocol))})
	}

	if len(hosts) == 0 {
		return []OpenvpnServer{{Host: "kubernetes services not found"}}, err
	}

	return hosts, nil
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
	}

	certPem, _ := pem.Decode(caCert)
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	err := os.Chmod(*easyrsaDirPath+"/pki", 0755)
	if err != nil {
		log.Error(err)
	}
	err = os.Chmod(*easyrsaDirPath+"/pki/crl.pem", 0644)
	if err != nil {
		log.Error(err)
	}
}
