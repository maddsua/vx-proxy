package main

import (
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

func (this authenticator) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {

	if r.Code != radius.CodeAccessRequest {
		slog.Warn("invalid auth handler packet",
			slog.Int("code", int(r.Code)),
			slog.String("code_text", r.Code.String()))
		return
	}

	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)

	var user *UserConfig
	for _, entry := range this.Users {
		if entry.Name == username && entry.Pass == password {
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
			slog.String("username", username),
			slog.String("password", password),
			slog.String("client_ip", clientIP.String()),
			slog.String("nas_ip", nasIP.String()),
			slog.Int("nas_port", int(nasPort)))
		return
	}

	if user.ProxyAddr != "" && user.ProxyAddr != nasIP.String() {
		w.Write(r.Response(radius.CodeAccessReject))
		slog.Info("Auth: Rejected: ProxyAddr denied",
			slog.String("nas_addr", r.RemoteAddr.String()),
			slog.String("username", username),
			slog.String("password", password),
			slog.String("client_ip", clientIP.String()),
			slog.String("nas_ip", nasIP.String()),
			slog.Int("nas_port", int(nasPort)))
		return
	}

	if user.ProxyPort != 0 && user.ProxyPort != int(nasPort) {
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
		rfc2865.SessionTimeout_Set(response, rfc2865.SessionTimeout(user.SessionTTL))
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
