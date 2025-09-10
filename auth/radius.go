package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	radius "github.com/maddsua/layeh-radius"
	"github.com/maddsua/layeh-radius/rfc2865"
	"github.com/maddsua/layeh-radius/rfc2866"
	"github.com/maddsua/layeh-radius/rfc3162"
	"github.com/maddsua/layeh-radius/rfc3576"
	"github.com/maddsua/layeh-radius/rfc4679"
	"github.com/maddsua/layeh-radius/rfc6911"
	"github.com/maddsua/vx-proxy/utils"
)

type RadiusConfig struct {
	AuthAddr  string `yaml:"auth_addr"`
	AcctAddr  string `yaml:"acct_addr"`
	ListenDAC string `yaml:"listen_dac"`
	Secret    string `yaml:"secret"`
}

func (this *RadiusConfig) Validate() error {

	utils.ExpandEnv(&this.ListenDAC)
	utils.ExpandEnv(&this.AuthAddr)
	utils.ExpandEnv(&this.AcctAddr)
	utils.ExpandEnv(&this.Secret)

	if this.AuthAddr == "" {
		return errors.New("auth_addr is empty")
	} else if !utils.NetAddrFormatValid(this.AuthAddr) {
		return errors.New("auth_addr format invalid")
	}

	if this.AcctAddr == "" {
		this.AcctAddr = this.AuthAddr
	} else if !utils.NetAddrFormatValid(this.AcctAddr) {
		return errors.New("acct_addr format invalid")
	}

	if this.Secret == "" {
		return errors.New("secret is empty")
	}

	if this.ListenDAC == "" {
		this.ListenDAC = ":3799"
	} else if !utils.NetAddrFormatValid(this.ListenDAC) {
		return errors.New("listen_dac format invalid")
	}

	return nil
}

func (this RadiusConfig) ServiceID() string {
	return "radius"
}

func (this RadiusConfig) BindsPorts() []string {

	var ports []string

	var add = func(addr string) {
		if _, port, err := net.SplitHostPort(addr); err == nil {
			ports = append(ports, fmt.Sprintf("%s/udp", port))
		}
	}

	add(this.ListenDAC)

	return ports
}

func NewRadiusController(protoCfg RadiusConfig, sessOpts SessionOptions) (*radiusController, error) {

	ctx, cancel := context.WithCancel(context.Background())

	this := &radiusController{
		authAddr:  protoCfg.AuthAddr,
		acctAddr:  protoCfg.AcctAddr,
		secret:    []byte(protoCfg.Secret),
		ctx:       ctx,
		cancelCtx: cancel,

		defaultSessOpts: sessOpts,
		sessState:       sessionState{entries: map[string]expirer{}},
		refreshTicker:   time.NewTicker(10 * time.Second),
	}

	this.dacServer = &radius.PacketServer{
		Handler:      radius.HandlerFunc(this.dacHandler),
		SecretSource: radius.StaticSecretSource(this.secret),
		Addr:         protoCfg.ListenDAC,
	}

	if host, _, _ := net.SplitHostPort(this.dacServer.Addr); strings.ToLower(host) == "localhost" {
		slog.Warn("RADIUS: 'localhost' is set as a DAC address. This may or may not bind only to IPv4 UDP loopback address. Please consider using a specific address or an <unspecified>")
	}

	var err error
	if this.dacListener, err = net.ListenPacket("udp", this.dacServer.Addr); err != nil {
		return nil, err
	}

	go this.asyncDac()
	go this.asyncRefresh()

	return this, nil
}

type radiusController struct {
	authAddr string
	acctAddr string
	secret   []byte

	sessState       sessionState
	defaultSessOpts SessionOptions
	refreshTicker   *time.Ticker

	ctx       context.Context
	cancelCtx context.CancelFunc
	wg        sync.WaitGroup

	dacServer   *radius.PacketServer
	dacListener net.PacketConn

	errorRate radiusErrorRate
}

func (this *radiusController) Type() string {
	return "radius"
}

func (this *radiusController) ErrorRate() float64 {
	return this.errorRate.Rate()
}

func (this *radiusController) Shutdown(ctx context.Context) error {

	//	 cancel internal contexts
	this.cancelCtx()
	this.refreshTicker.Stop()
	this.dacServer.Shutdown(ctx)
	this.dacListener.Close()

	this.wg.Wait()

	var terminateSession = func(wg *sync.WaitGroup, sess *Session) {

		defer wg.Done()

		sess.Close()

		if err := this.acctStopSession(ctx, sess); err != nil {
			slog.Error("Failed to write terminated session accounting data",
				slog.String("sid", sess.ID.String()),
				slog.String("err", err.Error()))
		}
	}

	//	report all active sessions accounting and terminate them
	if ctx.Err() == nil {

		var wg sync.WaitGroup

		for _, entry := range this.sessState.Entries() {

			if sess, ok := entry.Val.(*Session); ok {
				wg.Add(1)
				go terminateSession(&wg, sess)
			}

			this.sessState.Del(entry.Key)
		}

		wg.Wait()
	}

	return ctx.Err()
}

func (this *radiusController) asyncDac() {

	this.wg.Add(1)
	defer this.wg.Done()

	if err := this.dacServer.Serve(this.dacListener); err != nil && this.ctx.Err() == nil {
		slog.Error("RADIUS: DAC: Server error",
			slog.String("err", err.Error()))
	}
}

func (this *radiusController) asyncRefresh() {

	this.wg.Add(1)
	defer this.wg.Done()

	const updateInterval = time.Minute

	var refreshSession = func(ctx context.Context, wg *sync.WaitGroup, stateKey string, sess *Session) {

		defer wg.Done()

		switch {

		case sess.IsCancelled():

			slog.Debug("RADIUS: Session terminated",
				slog.String("sid", sess.ID.String()),
				slog.String("reason", "ttl"),
				slog.Int("acct_rx", int(sess.Traffic.AcctRx.Load())),
				slog.Int("acct_tx", int(sess.Traffic.AcctTx.Load())))

			sess.Close()

			if err := this.acctStopSession(ctx, sess); err != nil {
				slog.Error("RADIUS: Error stopping session accounting",
					slog.String("sid", sess.ID.String()),
					slog.String("stop_reason", "cancelled"),
					slog.String("err", err.Error()))
			}

			this.sessState.Del(stateKey)

		case sess.IsIdle():

			slog.Debug("RADIUS: Session terminated",
				slog.String("sid", sess.ID.String()),
				slog.String("reason", "idle"),
				slog.Int("acct_rx", int(sess.Traffic.AcctRx.Load())),
				slog.Int("acct_tx", int(sess.Traffic.AcctTx.Load())))

			sess.Close()

			if err := this.acctStopSession(ctx, sess); err != nil {
				slog.Error("RADIUS: Error stopping session accounting",
					slog.String("sid", sess.ID.String()),
					slog.String("stop_reason", "idle"),
					slog.String("err", err.Error()))
			}

			this.sessState.Del(stateKey)

		case time.Since(sess.lastUpdated) > updateInterval:

			if sess.Traffic.AcctRx.Load() > 0 || sess.Traffic.AcctTx.Load() > 0 {

				slog.Debug("RADIUS: Session accounting update",
					slog.String("sid", sess.ID.String()),
					slog.Int("rx", int(sess.Traffic.AcctRx.Load())),
					slog.Int("tx", int(sess.Traffic.AcctTx.Load())))

				if err := this.acctUpdateSession(ctx, sess); err != nil {
					slog.Error("RADIUS: Failed to update session accounting",
						slog.String("sid", sess.ID.String()),
						slog.String("err", err.Error()))
				} else {
					sess.lastUpdated = time.Now()
				}
			}
		}
	}

	var iterate = func() {

		ctx, cancel := context.WithTimeout(this.ctx, time.Minute)
		defer cancel()

		var wg sync.WaitGroup

		for _, entry := range this.sessState.Entries() {

			switch val := entry.Val.(type) {

			case *Session:
				wg.Add(1)
				go refreshSession(ctx, &wg, entry.Key, val)

			case *CredentialsMiss:
				if val.Expired() {
					slog.Debug("RADIUS: Credentials cache miss reset",
						slog.String("username", val.Username))
					this.sessState.Del(entry.Key)
				}

			default:
				if entry.Val.Expired() {
					slog.Warn("RADIUS: Expired key removed",
						slog.String("key", entry.Key),
						slog.String("type", fmt.Sprintf("%T", entry.Val)))
					this.sessState.Del(entry.Key)
				}
			}
		}

		wg.Wait()
	}

	done := this.ctx.Done()

	for {
		select {
		case <-this.refreshTicker.C:
			iterate()
		case <-done:
			return
		}
	}
}

func (this *radiusController) exchangeAuth(ctx context.Context, packet *radius.Packet) (*radius.Packet, error) {
	return radius.Exchange(ctx, packet, this.authAddr)
}

func (this *radiusController) exchangeAcct(ctx context.Context, packet *radius.Packet) (*radius.Packet, error) {
	return radius.Exchange(ctx, packet, this.acctAddr)
}

func (this *radiusController) WithPassword(ctx context.Context, auth PasswordAuth) (*Session, error) {

	if auth.Username = strings.TrimSpace(auth.Username); auth.Username == "" {
		return nil, errors.New("invalid credentials format: username is empty")
	} else if len(auth.Username) > 64 {
		return nil, errors.New("invalid credentials format: username too long")
	} else if len(auth.Password) > 64 {
		return nil, errors.New("invalid credentials format: password too long")
	}

	hasher := sha256.New()
	hasher.Write([]byte(auth.Username))
	hasher.Write([]byte(auth.Password))
	hasher.Write(auth.ClientIP)
	hasher.Write(auth.NasAddr)
	hasher.Write([]byte(strconv.Itoa(auth.NasPort)))
	sessKey := "pwa_sha:" + hex.EncodeToString(hasher.Sum(nil))

	if sess, has := this.sessState.LoadSession(sessKey); has && sess == nil {
		return nil, ErrUnauthorized
	} else if sess != nil {
		sess.BumpActive()
		return sess, nil
	}

	sess, err := this.authRequestAccess(ctx, auth)
	if err != nil {

		if err == ErrUnauthorized {
			this.sessState.Store(sessKey, &CredentialsMiss{
				Username: auth.Username,
				Expires:  time.Now().Add(time.Minute),
			})
		}

		return nil, err
	}

	if err := this.acctStartSession(ctx, sess); err != nil {
		return nil, err
	}

	slog.Debug("RADIUS: Authorized session",
		slog.String("method", "passwd"),
		slog.String("username", auth.Username),
		slog.String("sid", sess.ID.String()),
		slog.Int("dl", sess.Traffic.ActualRateRx),
		slog.Int("up", sess.Traffic.ActualRateTx),
		slog.Int("max_dl", sess.Traffic.MaximumRateRx),
		slog.Int("max_up", sess.Traffic.MaximumRateTx),
		slog.Int("min_dl", sess.Traffic.MinimumRateRx),
		slog.Int("min_up", sess.Traffic.MinimumRateTx))

	this.sessState.Store(sessKey, sess)

	return sess, nil
}

func (this *radiusController) authRequestAccess(ctx context.Context, auth PasswordAuth) (*Session, error) {

	defer this.errorRate.Add()

	req := radius.New(radius.CodeAccessRequest, this.secret)

	if err := rfc2865.UserName_SetString(req, auth.Username); err != nil {
		panic(fmt.Errorf("set: rfc2865.UserName: %v", err))
	}

	if err := rfc2865.UserPassword_SetString(req, auth.Password); err != nil {
		panic(fmt.Errorf("set: rfc2865.UserPassword: %v", err))
	}

	if auth.ClientIP != nil {

		val := fmt.Sprintf("%s/%d 0.0.0.0",
			auth.ClientIP.String(),
			utils.AddrMaskSize(auth.ClientIP))

		if err := rfc2865.FramedRoute_Set(req, []byte(val)); err != nil {
			panic(fmt.Errorf("set: rfc2865.FramedRoute: %v", err))
		}
	}

	switch len(auth.NasAddr) {

	case net.IPv4len:
		if err := rfc2865.NASIPAddress_Set(req, auth.NasAddr); err != nil {
			panic(fmt.Errorf("set: rfc2865.NASIPAddress: %v", err))
		}

	case net.IPv6len:
		if err := rfc3162.NASIPv6Address_Set(req, auth.NasAddr); err != nil {
			panic(fmt.Errorf("set: rfc3162.NASIPv6Address: %v", err))
		}
	}

	if err := rfc2865.NASPort_Set(req, rfc2865.NASPort(auth.NasPort)); err != nil {
		panic(fmt.Errorf("set: rfc2865.NASPort: %v", err))
	}

	resp, err := this.exchangeAuth(ctx, req)
	if err != nil {
		this.errorRate.AddError()
		return nil, fmt.Errorf("radius access request failed: %v", err)
	}

	req = nil

	if resp.Code == radius.CodeAccessReject {
		return nil, ErrUnauthorized
	} else if resp.Code != radius.CodeAccessAccept {
		this.errorRate.AddError()
		return nil, fmt.Errorf("radius access request failed: unexpected response code: %d", resp.Code)
	}

	sessUuid, err := uuid.FromBytes(rfc2866.AcctSessionID_Get(resp))
	if err != nil {
		return nil, errors.New("invalid radius response: Acct-Session-ID is missing or not a valid uuid")
	}

	sess := Session{
		ID:       sessUuid,
		UserName: &auth.Username,

		FramedIP: auth.NasAddr,

		Traffic: NewTrafficCtl(),

		lastActivity: time.Now(),
		lastUpdated:  time.Now(),
	}

	if addr := rfc2865.FramedIPAddress_Get(resp); addr != nil {

		if has, _ := utils.AddrAssigned(addr); !has {
			slog.Warn("Auth: RADIUS: FramedIPAddress not assigned to the host",
				slog.String("addr", addr.String()))
		} else {
			sess.FramedIP = addr
		}

	} else if val := rfc6911.FramedIPv6Address_Get(resp); val != nil {

		if has, _ := utils.AddrAssigned(addr); !has {
			slog.Warn("Auth: RADIUS: FramedIPv6Address not assigned to the host",
				slog.String("addr", addr.String()))
		} else {
			sess.FramedIP = addr
		}
	}

	this.applySessionOpts(&sess, resp)

	sess.ctx, sess.cancelCtx = context.WithTimeout(context.Background(), sess.Timeout)

	return &sess, nil
}

func (this *radiusController) applySessionOpts(sess *Session, packet *radius.Packet) {

	if sess.ctx == nil {
		if val := rfc2865.SessionTimeout_Get(packet); val > 0 {
			sess.Timeout = time.Duration(val) * time.Second
		} else {
			sess.Timeout = this.defaultSessOpts.Timeout
		}
	}

	if val := rfc2865.IdleTimeout_Get(packet); val > 0 {
		sess.IdleTimeout = time.Duration(val) * time.Second
	} else {
		sess.IdleTimeout = this.defaultSessOpts.IdleTimeout
	}

	if val := rfc4679.ActualDataRateDownstream_Get(packet); val > 0 {
		sess.Traffic.ActualRateRx = int(val)
	} else {
		sess.Traffic.ActualRateRx = this.defaultSessOpts.ActualRateRx
	}

	if val := rfc4679.ActualDataRateUpstream_Get(packet); val > 0 {
		sess.Traffic.ActualRateTx = int(val)
	} else {
		sess.Traffic.ActualRateTx = this.defaultSessOpts.ActualRateTx
	}

	if val := rfc4679.MaximumDataRateDownstream_Get(packet); val > 0 {
		sess.Traffic.MaximumRateRx = int(val)
	} else {
		sess.Traffic.MaximumRateRx = this.defaultSessOpts.MaximumRateRx
	}

	if val := rfc4679.MaximumDataRateUpstream_Get(packet); val > 0 {
		sess.Traffic.MaximumRateTx = int(val)
	} else {
		sess.Traffic.MaximumRateTx = this.defaultSessOpts.MaximumRateTx
	}

	if val := rfc4679.MinimumDataRateDownstream_Get(packet); val > 0 {
		sess.Traffic.MinimumRateRx = int(val)
	} else {
		sess.Traffic.MinimumRateRx = this.defaultSessOpts.MinimumRateRx
	}

	if val := rfc4679.MinimumDataRateUpstream_Get(packet); val > 0 {
		sess.Traffic.MinimumRateTx = int(val)
	} else {
		sess.Traffic.MinimumRateTx = this.defaultSessOpts.MinimumRateTx
	}

	if val := rfc2865.PortLimit_Get(packet); val > 0 {
		sess.Traffic.ConnectionLimit = int(val)
	} else {
		sess.Traffic.ConnectionLimit = this.defaultSessOpts.ConnectionLimit
	}
}

func (this *radiusController) acctStartSession(ctx context.Context, sess *Session) error {

	defer this.errorRate.Add()

	req := radius.New(radius.CodeAccountingRequest, this.secret)

	if err := rfc2866.AcctStatusType_Set(req, rfc2866.AcctStatusType_Value_Start); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctStatusType: %v", err))
	}

	if err := rfc2866.AcctSessionID_Set(req, sess.ID[:]); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctSessionID: %v", err))
	}

	if _, err := this.exchangeAcct(ctx, req); err != nil {
		this.errorRate.AddError()
		return err
	}

	return nil
}

func (this *radiusController) acctUpdateSession(ctx context.Context, sess *Session) error {

	defer this.errorRate.Add()

	req := radius.New(radius.CodeAccountingRequest, this.secret)

	if err := rfc2866.AcctStatusType_Set(req, rfc2866.AcctStatusType_Value_InterimUpdate); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctStatusType: %v", err))
	}

	if err := rfc2866.AcctSessionID_Set(req, sess.ID[:]); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctSessionID: %v", err))
	}

	rxVolume := sess.Traffic.AcctRx.Load()
	if err := rfc2866.AcctInputOctets_Set(req, rfc2866.AcctInputOctets(rxVolume)); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctInputOctets: %v", err))
	}

	txVolume := sess.Traffic.AcctTx.Load()
	if err := rfc2866.AcctOutputOctets_Set(req, rfc2866.AcctOutputOctets(txVolume)); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctOutputOctets: %v", err))
	}

	if _, err := this.exchangeAcct(ctx, req); err != nil {
		this.errorRate.AddError()
		return err
	}

	sess.Traffic.AcctRx.Add(-rxVolume)
	sess.Traffic.AcctTx.Add(-txVolume)

	return nil
}

func (this *radiusController) acctStopSession(ctx context.Context, sess *Session) error {

	defer this.errorRate.Add()

	req := radius.New(radius.CodeAccountingRequest, this.secret)

	if err := rfc2866.AcctStatusType_Set(req, rfc2866.AcctStatusType_Value_Stop); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctStatusType: %v", err))
	}

	if err := rfc2866.AcctSessionID_Set(req, sess.ID[:]); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctSessionID: %v", err))
	}

	if err := rfc2866.AcctInputOctets_Set(req, rfc2866.AcctInputOctets(sess.Traffic.AcctRx.Load())); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctInputOctets: %v", err))
	}

	if err := rfc2866.AcctOutputOctets_Set(req, rfc2866.AcctOutputOctets(sess.Traffic.AcctTx.Load())); err != nil {
		panic(fmt.Errorf("set: rfc2866.AcctOutputOctets: %v", err))
	}

	if _, err := this.exchangeAcct(ctx, req); err != nil {
		this.errorRate.AddError()
		return err
	}

	sess.Traffic.AcctRx.Store(0)
	sess.Traffic.AcctRx.Store(0)

	return nil
}

func (this *radiusController) dacHandler(wrt radius.ResponseWriter, req *radius.Request) {

	switch req.Code {
	case radius.CodeDisconnectRequest:
		this.dacHandleDisconnect(wrt, req)
	case radius.CodeCoARequest:
		this.dacHandleCOA(wrt, req)
	default:
		slog.Error("RADIUS DAC: Unsupported code",
			slog.String("code", req.Code.String()),
			slog.String("dac_addr", req.RemoteAddr.(*net.UDPAddr).IP.String()))
	}
}

func (this *radiusController) dacHandleDisconnect(wrt radius.ResponseWriter, req *radius.Request) {

	sessID := SessionIdFromBytes(rfc2866.AcctSessionID_Get(req.Packet))
	if !sessID.Valid {
		slog.Error("RADIUS DAC: DM doesn't contain a valid session id",
			slog.String("ip", req.RemoteAddr.(*net.UDPAddr).IP.String()))
		resp := req.Response(radius.CodeDisconnectNAK)
		rfc3576.ErrorCause_Set(resp, rfc3576.ErrorCause_Value_SessionContextNotFound)
		wrt.Write(resp)
		return
	}

	sess, has := this.sessState.LookupSessionEntry(sessID.UUID)
	if !has {

		slog.Warn("RADIUS DAC: DM session ID not found",
			slog.String("sid", sessID.UUID.String()),
			slog.String("dac_addr", req.RemoteAddr.String()))

		resp := req.Response(radius.CodeDisconnectNAK)
		rfc3576.ErrorCause_Set(resp, rfc3576.ErrorCause_Value_SessionContextNotFound)
		wrt.Write(resp)

		return
	}

	sess.cancelCtx()

	slog.Info("RADIUS DAC: DM OK",
		slog.String("sid", sess.ID.String()),
		slog.String("dac_addr", req.RemoteAddr.String()))

	wrt.Write(req.Response(radius.CodeDisconnectACK))
}

func (this *radiusController) dacHandleCOA(wrt radius.ResponseWriter, req *radius.Request) {

	sessID := SessionIdFromBytes(rfc2866.AcctSessionID_Get(req.Packet))
	if !sessID.Valid {
		slog.Error("RADIUS DAC: CoA message doesn't contain a valid session id",
			slog.String("dac_addr", req.RemoteAddr.(*net.UDPAddr).IP.String()))
		return
	}

	sess, has := this.sessState.LookupSessionEntry(sessID.UUID)
	if !has {

		slog.Warn("RADIUS DAC: CoA session ID not found",
			slog.String("sid", sessID.UUID.String()),
			slog.String("dac_addr", req.RemoteAddr.String()))

		wrt.Write(req.Response(radius.CodeCoANAK))
		resp := req.Response(radius.CodeCoANAK)
		rfc3576.ErrorCause_Set(resp, rfc3576.ErrorCause_Value_SessionContextNotFound)
		wrt.Write(resp)

		return
	}

	this.applySessionOpts(sess, req.Packet)

	slog.Info("RADIUS DAC: CoA OK",
		slog.String("sid", sess.ID.String()),
		slog.Duration("idle_t", sess.IdleTimeout),
		slog.Int("dl", sess.Traffic.ActualRateRx),
		slog.Int("up", sess.Traffic.ActualRateTx),
		slog.Int("max_dl", sess.Traffic.MaximumRateRx),
		slog.Int("max_up", sess.Traffic.MaximumRateTx),
		slog.Int("min_dl", sess.Traffic.MinimumRateRx),
		slog.Int("min_up", sess.Traffic.MinimumRateTx),
		slog.String("dac_addr", req.RemoteAddr.String()))

	wrt.Write(req.Response(radius.CodeCoAACK))
}

type radiusErrorRate struct {
	countdown time.Time
	total     atomic.Int64
	errors    atomic.Int64
}

func (this *radiusErrorRate) refresh() {
	if this.countdown.IsZero() {
		this.countdown = time.Now()
	} else if time.Since(this.countdown) > time.Minute {
		this.countdown = time.Now()
		this.total.Store(0)
		this.errors.Store(0)
	}
}

func (this *radiusErrorRate) Add() {
	this.refresh()
	this.total.Add(1)
}

func (this *radiusErrorRate) AddError() {
	this.refresh()
	this.errors.Add(1)
}

func (this *radiusErrorRate) Rate() float64 {

	total := this.total.Load()
	errors := this.errors.Load()

	if total == 0 {
		return 0
	}

	return float64(errors) / float64(total)
}
