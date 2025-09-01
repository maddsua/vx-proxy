package main

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/google/uuid"
	radius "github.com/maddsua/layeh-radius"
	"github.com/maddsua/layeh-radius/rfc2865"
	"github.com/maddsua/layeh-radius/rfc2866"
	"github.com/maddsua/layeh-radius/rfc3162"
	"github.com/maddsua/layeh-radius/rfc4372"
	"github.com/maddsua/layeh-radius/rfc4679"
	"github.com/maddsua/layeh-radius/rfc5580"
)

type authenticator struct {
	Users []UserConfig
}

func (this authenticator) ServeRADIUS(w radius.ResponseWriter, req *radius.Request) {

	if req.Code != radius.CodeAccessRequest {
		slog.Warn("invalid auth handler packet",
			slog.Int("code", int(req.Code)),
			slog.String("code_text", req.Code.String()))
		return
	}

	username := rfc2865.UserName_GetString(req.Packet)
	password := rfc2865.UserPassword_GetString(req.Packet)

	var user *UserConfig
	for _, entry := range this.Users {
		if entry.Name == username && entry.Pass == password {
			user = &entry
			break
		}
	}

	clientIP := net.IP(rfc5580.LocationData_Get(req.Packet))
	nasIP := net.IP(rfc2865.NASIPAddress_Get(req.Packet))
	if nasIP == nil {
		nasIP = net.IP(rfc3162.NASIPv6Address_Get(req.Packet))
	}

	nasPort := rfc2865.NASPort_Get(req.Packet)

	if user == nil {
		w.Write(req.Response(radius.CodeAccessReject))
		slog.Info("Auth: Rejected: Invalid password",
			slog.String("username", username),
			slog.String("password", password),
			slog.String("client_ip", clientIP.String()),
			slog.String("nas_ip", nasIP.String()),
			slog.Int("nas_port", int(nasPort)))
		return
	}

	if user.ProxyAddr != "" && user.ProxyAddr != nasIP.String() {
		w.Write(req.Response(radius.CodeAccessReject))
		slog.Info("Auth: Rejected: ProxyAddr denied",
			slog.String("nas_addr", req.RemoteAddr.String()),
			slog.String("username", username),
			slog.String("password", password),
			slog.String("client_ip", clientIP.String()),
			slog.String("nas_ip", nasIP.String()),
			slog.Int("nas_port", int(nasPort)))
		return
	}

	if user.ProxyPort != 0 && user.ProxyPort != int(nasPort) {
		w.Write(req.Response(radius.CodeAccessReject))
		slog.Info("Auth: Rejected: Port denied",
			slog.String("nas_addr", req.RemoteAddr.String()),
			slog.String("username", username),
			slog.String("password", password),
			slog.String("client_ip", clientIP.String()),
			slog.String("nas_ip", nasIP.String()),
			slog.Int("nas_port", int(nasPort)))
		return
	}

	resp := req.Response(radius.CodeAccessAccept)
	slog.Info("Auth: Accepted",
		slog.String("nas_addr", req.RemoteAddr.String()),
		slog.String("username", username),
		slog.String("password", password),
		slog.String("client_ip", clientIP.String()),
		slog.String("nas_ip", nasIP.String()),
		slog.Int("nas_port", int(nasPort)))

	if user.MaxRx > 0 {
		if err := rfc4679.MaximumDataRateDownstream_Set(resp, rfc4679.MaximumDataRateDownstream(user.MaxRx)); err != nil {
			panic(fmt.Errorf("rfc4679.MaximumDataRateDownstream_Set: %v", err))
		}
	}

	if user.MaxTx > 0 {
		if err := rfc4679.MaximumDataRateUpstream_Set(resp, rfc4679.MaximumDataRateUpstream(user.MaxTx)); err != nil {
			panic(fmt.Errorf("rfc4679.MaximumDataRateUpstream_Set: %v", err))
		}
	}

	if user.SessionTTL > 0 {
		if err := rfc2865.SessionTimeout_Set(resp, rfc2865.SessionTimeout(user.SessionTTL)); err != nil {
			panic(fmt.Errorf("rfc2865.SessionTimeout_Set: %v", err))
		}
	}

	sessionID := uuid.New()

	if err := rfc2866.AcctSessionID_Set(resp, sessionID[:]); err != nil {
		panic(fmt.Errorf("rfc2866.AcctSessionID_Set: %v", err))
	}

	userID := uuid.New()

	if err := rfc4372.ChargeableUserIdentity_Set(resp, userID[:]); err != nil {
		panic(fmt.Errorf("rfc4372.ChargeableUserIdentity_Set: %v", err))
	}

	w.Write(resp)
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
