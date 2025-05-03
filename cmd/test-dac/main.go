package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	radius "github.com/maddsua/layeh-radius"
	"github.com/maddsua/layeh-radius/rfc2865"
	"github.com/maddsua/layeh-radius/rfc2866"
	"github.com/maddsua/layeh-radius/rfc3162"
	"github.com/maddsua/layeh-radius/rfc4372"
	"github.com/maddsua/layeh-radius/rfc4679"
	"github.com/maddsua/layeh-radius/rfc5580"
)

type User struct {
	Name       string
	Password   string
	NasPort    int
	MaxRx      int
	MaxTx      int
	SessionTTL time.Duration
}

var sampleUsers = []User{
	{
		Name:       "maddsua",
		Password:   "superstrongpass123",
		MaxRx:      0,
		MaxTx:      0,
		NasPort:    0,
		SessionTTL: 0,
	},
	{
		Name:       "timmy",
		Password:   "12345",
		MaxRx:      100_000,
		MaxTx:      100_000,
		NasPort:    8820,
		SessionTTL: 5 * time.Minute,
	},
	{
		Name:       "tester",
		Password:   "rivomtv28cny6i",
		MaxRx:      1_000_000,
		MaxTx:      100_000,
		NasPort:    8811,
		SessionTTL: 5 * time.Minute,
	},
}

func main() {

	cmdFlag := flag.String("cmd", "", "[dac command] radius commmand to run")
	sidFlag := flag.String("sid", "", "[dac command] provide session id to manage")
	hostFlag := flag.String("host", "localhost:3799", "[dac command]vx host addr")
	maxRate := flag.Int("maxrate", 0, "[dac command] max connection rate")
	secretFlag := flag.String("secret", "secret", "radius protocol secret")
	flag.Parse()

	if *cmdFlag != "" {
		cmdFn(*cmdFlag, *hostFlag, *secretFlag, *sidFlag, *maxRate)
		return
	}

	authServer := radius.PacketServer{
		Handler:      radius.HandlerFunc(authHandler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
		Addr:         ":1812",
	}

	acctServer := radius.PacketServer{
		Handler:      radius.HandlerFunc(acctHandler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
		Addr:         ":1813",
	}

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {

		defer wg.Done()

		log.Printf("Starting server on %s", authServer.Addr)
		if err := authServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {

		defer wg.Done()

		log.Printf("Starting server on %s", acctServer.Addr)
		if err := acctServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	wg.Wait()
}

func authHandler(w radius.ResponseWriter, r *radius.Request) {

	if r.Code != radius.CodeAccessRequest {
		slog.Warn("invalid auth handler packet",
			slog.Int("code", int(r.Code)),
			slog.String("code_text", r.Code.String()))
		return
	}

	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)

	var user *User
	for _, entry := range sampleUsers {
		if entry.Name == username && entry.Password == password {
			user = &entry
			break
		}
	}

	clientIP := net.IP(rfc5580.LocationData_Get(r.Packet))
	nasIP := net.IP(rfc2865.NASIPAddress_Get(r.Packet))
	if nasIP == nil {
		nasIP = net.IP(rfc3162.NASIPv6Address_Get(r.Packet))
	}

	nasPort := rfc2865.NASPort_Get(r.Packet)

	if user == nil {
		w.Write(r.Response(radius.CodeAccessReject))
		slog.Info("Auth: Rejected: Invalid password",
			slog.String("nas_addr", r.RemoteAddr.String()),
			slog.String("username", username),
			slog.String("password", password),
			slog.String("client_ip", clientIP.String()),
			slog.String("nas_ip", nasIP.String()),
			slog.Int("nas_port", int(nasPort)))
		return
	}

	if user.NasPort != 0 && user.NasPort != int(nasPort) {
		w.Write(r.Response(radius.CodeAccessReject))
		slog.Info("Auth: Rejected: Port denied",
			slog.String("nas_addr", r.RemoteAddr.String()),
			slog.String("username", username),
			slog.String("password", password),
			slog.String("client_ip", clientIP.String()),
			slog.String("nas_ip", nasIP.String()),
			slog.Int("nas_port", int(nasPort)))
		return
	}

	response := r.Response(radius.CodeAccessAccept)
	slog.Info("Auth: Accepted",
		slog.String("nas_addr", r.RemoteAddr.String()),
		slog.String("username", username),
		slog.String("password", password),
		slog.String("client_ip", clientIP.String()),
		slog.String("nas_ip", nasIP.String()),
		slog.Int("nas_port", int(nasPort)))

	if user.MaxRx > 0 {
		rfc4679.MaximumDataRateDownstream_Set(response, rfc4679.MaximumDataRateDownstream(user.MaxRx))
	}

	if user.MaxTx > 0 {
		rfc4679.MaximumDataRateUpstream_Set(response, rfc4679.MaximumDataRateUpstream(user.MaxTx))
	}

	if user.SessionTTL > 0 {
		rfc2865.SessionTimeout_Set(response, rfc2865.SessionTimeout(user.SessionTTL.Seconds()))
	}

	sessionID := uuid.New()
	rfc2866.AcctSessionID_Set(response, sessionID[:])

	userID := uuid.New()
	rfc4372.ChargeableUserIdentity_Set(response, userID[:])

	w.Write(response)

}

func acctHandler(w radius.ResponseWriter, r *radius.Request) {

	if r.Code != radius.CodeAccountingRequest {
		slog.Warn("invalid acct handler packet",
			slog.Int("code", int(r.Code)),
			slog.String("code_text", r.Code.String()))
		return
	}

	response := r.Response(radius.CodeAccountingResponse)

	rxCount := rfc2866.AcctInputOctets_Get(r.Packet)
	txCount := rfc2866.AcctOutputOctets_Get(r.Packet)

	switch rfc2866.AcctStatusType_Get(r.Packet) {

	case rfc2866.AcctStatusType_Value_Start:

		sessionID, _ := uuid.FromBytes(rfc2866.AcctSessionID_Get(r.Packet))

		slog.Info("Accounting: Start",
			slog.String("sid", sessionID.String()))

	case rfc2866.AcctStatusType_Value_InterimUpdate:
		sessionID, _ := uuid.FromBytes(rfc2866.AcctSessionID_Get(r.Packet))
		slog.Info("Accounting: Update",
			slog.String("id", sessionID.String()),
			slog.Int64("rx", int64(rxCount)),
			slog.Int64("tx", int64(txCount)))

	case rfc2866.AcctStatusType_Value_Stop:
		sessionID, _ := uuid.FromBytes(rfc2866.AcctSessionID_Get(r.Packet))
		slog.Info("Accounting: Stop",
			slog.String("id", sessionID.String()),
			slog.Int64("rx", int64(rxCount)),
			slog.Int64("tx", int64(txCount)))

	default:
		slog.Warn("invalid acct handler status")
		return
	}

	w.Write(response)
}

func cmdFn(cmd string, host string, secret string, sid string, maxRate int) {

	sidUUID, err := uuid.Parse(sid)
	if err != nil {
		slog.Error("session id required",
			slog.String("flag", "-sid=uuid"),
			slog.String("err", err.Error()))
		os.Exit(1)
	}

	switch cmd {
	case "disconnect":
		if err := sendDisconnect(host, secret, sidUUID); err != nil {
			slog.Error("disconnect request failed",
				slog.String("err", err.Error()))
			os.Exit(1)
		}
	case "coa":
		if err := sendCoa(host, secret, sidUUID, maxRate); err != nil {
			slog.Error("coa request failed",
				slog.String("err", err.Error()))
			os.Exit(1)
		}
	default:
		slog.Error("unknown command")
		os.Exit(1)
	}
}

func sendDisconnect(host string, secret string, sid uuid.UUID) error {

	req := radius.New(radius.CodeDisconnectRequest, []byte(secret))

	rfc2866.AcctSessionID_Set(req, sid[:])

	resp, err := radius.Exchange(context.Background(), req, host)
	if err != nil {
		return err
	}

	if resp.Code != radius.CodeDisconnectACK {
		return errors.New(req.Code.String())
	}

	return err
}

func sendCoa(host string, secret string, sid uuid.UUID, maxRate int) error {

	req := radius.New(radius.CodeCoARequest, []byte(secret))

	rfc2866.AcctSessionID_Set(req, sid[:])

	rfc4679.MaximumDataRateDownstream_Set(req, rfc4679.MaximumDataRateDownstream(maxRate))
	rfc4679.MaximumDataRateUpstream_Set(req, rfc4679.MaximumDataRateUpstream(maxRate))

	resp, err := radius.Exchange(context.Background(), req, host)
	if err != nil {
		return err
	}

	if resp.Code != radius.CodeCoAACK {
		return errors.New(req.Code.String())
	}

	return err
}
