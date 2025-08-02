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
	"time"

	"github.com/google/uuid"
	radius "github.com/maddsua/layeh-radius"
	"github.com/maddsua/layeh-radius/rfc2865"
	"github.com/maddsua/layeh-radius/rfc2866"
	"github.com/maddsua/layeh-radius/rfc3162"
	"github.com/maddsua/layeh-radius/rfc3576"
	"github.com/maddsua/layeh-radius/rfc4372"
	"github.com/maddsua/layeh-radius/rfc4679"
	"github.com/maddsua/layeh-radius/rfc5580"
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

	return nil
}

func NewRadiusController(cfg RadiusConfig) (Controller, error) {

	if cfg.AuthAddr == "" {
		return nil, errors.New("invalid opt: AuthAddr is empty")
	} else if cfg.AcctAddr == "" {
		cfg.AcctAddr = cfg.AuthAddr
	}

	if cfg.Secret == "" {
		return nil, errors.New("invalid opt: Secret is empty")
	}

	listenDac := cfg.ListenDAC
	if listenDac == "" {
		listenDac = ":3799"
	}

	slog.Info("RADIUS auth module enabled",
		slog.String("auth_addr", cfg.AuthAddr),
		slog.String("acct_addr", cfg.AcctAddr),
		slog.String("listen_dac", listenDac))

	ctx, cancel := context.WithCancel(context.Background())

	this := &radiusController{
		authAddr:      cfg.AuthAddr,
		acctAddr:      cfg.AcctAddr,
		secret:        []byte(cfg.Secret),
		refreshTicker: time.NewTicker(10 * time.Second),
		ctx:           ctx,
		cancelCtx:     cancel,
		stateCache:    map[string]CacheEntry{},
	}

	this.dacServer = &radius.PacketServer{
		Handler:      radius.HandlerFunc(this.dacHandler),
		SecretSource: radius.StaticSecretSource(this.secret),
		Addr:         listenDac,
	}

	dacPacketServer, err := net.ListenPacket("udp", this.dacServer.Addr)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := this.dacServer.Serve(dacPacketServer); err != nil && this.ctx.Err() == nil {
			slog.Error("RADIUS: DAC: Server error",
				slog.String("err", err.Error()))
		}
	}()

	go this.refreshLoop()

	return this, nil
}

type radiusController struct {
	authAddr      string
	acctAddr      string
	secret        []byte
	stateCache    map[string]CacheEntry
	cacheMtx      sync.Mutex
	refreshTicker *time.Ticker
	ctx           context.Context
	cancelCtx     context.CancelFunc
	dacServer     *radius.PacketServer
}

func (this *radiusController) ID() string {
	return "radius:" + this.authAddr
}

func (this *radiusController) Close() error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//	 cancel internal contexts
	this.cancelCtx()
	this.refreshTicker.Stop()
	this.dacServer.Shutdown(ctx)

	//	wait for ticker routine to be done
	this.cacheMtx.Lock()
	defer this.cacheMtx.Unlock()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	//	report all active sessions as stopped
	var wg sync.WaitGroup

	for _, entry := range this.stateCache {

		sess, ok := entry.(*Session)
		if !ok {
			continue
		}

		if sess.Context != nil {

			wg.Add(1)

			go func() {
				defer wg.Done()
				if err := this.acctStopSession(ctx, sess); err != nil {
					fmt.Println(err)
				}
			}()
		}
	}

	wg.Wait()

	return nil
}

func (this *radiusController) exchangeAuth(ctx context.Context, packet *radius.Packet) (*radius.Packet, error) {
	return radius.Exchange(ctx, packet, this.authAddr)
}

func (this *radiusController) exchangeAcct(ctx context.Context, packet *radius.Packet) (*radius.Packet, error) {
	return radius.Exchange(ctx, packet, this.acctAddr)
}

func (this *radiusController) WithPassword(ctx context.Context, auth PasswordProxyAuth) (*Session, error) {

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

	sess, has := this.lookupCachedSession(sessKey)
	if has && sess == nil {
		return nil, ErrUnauthorized
	} else if sess != nil {
		return sess, nil
	}

	sess, err := this.authRequestAccess(ctx, auth)
	if err != nil {

		if err == ErrUnauthorized {
			this.storeCache(sessKey, &CredentialsMiss{
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
		slog.String("user", sess.ClientID))

	this.storeCache(sessKey, sess)
	return sess, nil
}

func (this *radiusController) lookupCachedSession(key string) (*Session, bool) {

	this.cacheMtx.Lock()
	defer this.cacheMtx.Unlock()

	entry := this.stateCache[key]

	if miss, ok := entry.(*CredentialsMiss); ok {
		if miss.Expires.After(time.Now()) {
			return nil, true
		}
	} else if sess, ok := entry.(*Session); ok {
		if sess.Context.Err() == nil {
			return sess, true
		}
	}

	return nil, false
}

func (this *radiusController) lookupCachedSessionByID(sid uuid.UUID) *Session {

	this.cacheMtx.Lock()
	defer this.cacheMtx.Unlock()

	for _, entry := range this.stateCache {

		sess, ok := entry.(*Session)
		if !ok {
			continue
		}

		if sess.ID == sid {
			return sess
		}
	}

	return nil
}

func (this *radiusController) storeCache(key string, entry CacheEntry) {

	if miss, ok := entry.(*CredentialsMiss); ok {
		if miss.Expires.IsZero() {
			panic(fmt.Sprintf("creds miss expiry time is zero on key '%s'", key))
		}
	} else if sess, ok := entry.(*Session); ok {
		if sess.Context == nil || sess.CancelContext == nil {
			panic(fmt.Sprintf("session context or cacncel function are invalid on key '%s'", key))
		}
	}

	this.cacheMtx.Lock()
	defer this.cacheMtx.Unlock()

	if old := this.stateCache[key]; old != nil {

		if sess, ok := old.(*Session); ok && sess.Context.Err() == nil {
			sess.CancelContext()
		}

		this.stateCache["mvctx:"+key+":"+uuid.NewString()] = old
	}

	this.stateCache[key] = entry
}

func (this *radiusController) authRequestAccess(ctx context.Context, auth PasswordProxyAuth) (*Session, error) {

	req := radius.New(radius.CodeAccessRequest, this.secret)

	if err := rfc2865.UserName_SetString(req, auth.Username); err != nil {
		panic(err)
	}

	if err := rfc2865.UserPassword_SetString(req, auth.Password); err != nil {
		panic(err)
	}

	if auth.ClientIP != nil {
		if err := rfc5580.LocationData_Set(req, auth.ClientIP); err != nil {
			panic(err)
		}
	}

	switch len(auth.NasAddr) {

	case net.IPv4len:
		if err := rfc2865.NASIPAddress_Set(req, auth.NasAddr); err != nil {
			panic(err)
		}

	case net.IPv6len:
		if err := rfc3162.NASIPv6Address_Set(req, auth.NasAddr); err != nil {
			panic(err)
		}
	}

	if auth.NasPort != 0 {
		if err := rfc2865.NASPort_Set(req, rfc2865.NASPort(auth.NasPort)); err != nil {
			panic(err)
		}
	}

	resp, err := this.exchangeAuth(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("radius access request failed: %v", err)
	}

	if resp.Code == radius.CodeAccessReject {
		return nil, ErrUnauthorized
	} else if resp.Code != radius.CodeAccessAccept {
		return nil, fmt.Errorf("radius access request failed: unexpected response code: %d", resp.Code)
	}

	sessUuid, err := uuid.FromBytes(rfc2866.AcctSessionID_Get(resp))
	if err != nil {
		return nil, errors.New("invalid radius response: Acct-Session-ID is missing or not a valid uuid")
	}

	sess := Session{
		ID:           sessUuid,
		UserName:     &auth.Username,
		ClientID:     "<nil>",
		LastActivity: time.Now(),
		LastActSync:  time.Now(),
	}

	if val := rfc4372.ChargeableUserIdentity_Get(resp); len(val) > 0 {
		if uid, err := uuid.FromBytes(val); err == nil {
			sess.ClientID = uid.String()
		} else if uid, err := uuid.Parse(string(val)); err == nil {
			sess.ClientID = uid.String()
		} else if uid, err := ParseTextID(string(val)); err == nil {
			sess.ClientID = uid
		}
	}

	if sessTimeout := rfc2865.SessionTimeout_Get(resp); sessTimeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(sessTimeout))
		sess.Context = ctx
		sess.CancelContext = cancel
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		sess.Context = ctx
		sess.CancelContext = cancel
	}

	if idleTimeout := rfc2865.IdleTimeout_Get(resp); idleTimeout > 0 {
		sess.IdleTimeout = time.Duration(idleTimeout) * time.Second
	} else {
		sess.IdleTimeout = 10 * time.Minute
	}

	sess.MaxDataRateRx = int(rfc4679.MaximumDataRateDownstream_Get(resp))
	sess.MaxDataRateTx = int(rfc4679.MaximumDataRateUpstream_Get(resp))

	return &sess, nil
}

func (this *radiusController) acctStartSession(ctx context.Context, sess *Session) error {

	req := radius.New(radius.CodeAccountingRequest, this.secret)

	if err := rfc2866.AcctStatusType_Set(req, rfc2866.AcctStatusType_Value_Start); err != nil {
		panic(err)
	}

	if err := rfc2866.AcctSessionID_Set(req, sess.ID[:]); err != nil {
		panic(err)
	}

	_, err := this.exchangeAcct(ctx, req)
	return err
}

func (this *radiusController) acctUpdateSession(ctx context.Context, sess *Session) error {

	var err error
	volRx, volTx := sess.AcctRxBytes.Load(), sess.AcctTxBytes.Load()

	if volRx == 0 && volTx == 0 {
		return nil
	}

	defer func() {
		if err == nil {
			sess.AcctRxBytes.Add(-volRx)
			sess.AcctTxBytes.Add(-volTx)
		}
	}()

	req := radius.New(radius.CodeAccountingRequest, this.secret)

	if err = rfc2866.AcctStatusType_Set(req, rfc2866.AcctStatusType_Value_InterimUpdate); err != nil {
		panic(err)
	}

	if err = rfc2866.AcctSessionID_Set(req, sess.ID[:]); err != nil {
		panic(err)
	}

	if err = rfc2866.AcctInputOctets_Set(req, rfc2866.AcctInputOctets(volRx)); err != nil {
		panic(err)
	}

	if err = rfc2866.AcctOutputOctets_Set(req, rfc2866.AcctOutputOctets(volTx)); err != nil {
		panic(err)
	}

	_, err = this.exchangeAcct(ctx, req)
	return err
}

func (this *radiusController) acctStopSession(ctx context.Context, sess *Session) error {

	var err error
	volRx, volTx := sess.AcctRxBytes.Load(), sess.AcctTxBytes.Load()

	defer func() {
		if err == nil {
			sess.AcctRxBytes.Store(0)
			sess.AcctTxBytes.Store(0)
		}
	}()

	req := radius.New(radius.CodeAccountingRequest, this.secret)

	if err = rfc2866.AcctStatusType_Set(req, rfc2866.AcctStatusType_Value_Stop); err != nil {
		panic(err)
	}

	if err = rfc2866.AcctSessionID_Set(req, sess.ID[:]); err != nil {
		panic(err)
	}

	if err = rfc2866.AcctInputOctets_Set(req, rfc2866.AcctInputOctets(volRx)); err != nil {
		panic(err)
	}

	if err = rfc2866.AcctOutputOctets_Set(req, rfc2866.AcctOutputOctets(volTx)); err != nil {
		panic(err)
	}

	_, err = this.exchangeAcct(ctx, req)
	return err
}

func (this *radiusController) refreshLoop() {

	var execRefresh = func() {

		ctx, cancel := context.WithTimeout(context.Background(), (time.Minute*10)/9)
		defer cancel()

		var wg sync.WaitGroup

		this.doRefresh(ctx, &wg)

		wg.Wait()
	}

	done := this.ctx.Done()

	for {
		select {
		case <-this.refreshTicker.C:
			execRefresh()
		case <-done:
			return
		}
	}
}

func (this *radiusController) doRefresh(ctx context.Context, wg *sync.WaitGroup) {

	this.cacheMtx.Lock()
	defer this.cacheMtx.Unlock()

	now := time.Now()
	syncActivityAfter := now.Add(-time.Minute)

	for key, entry := range this.stateCache {

		if miss, ok := entry.(*CredentialsMiss); ok {

			if miss.Expires.Before(now) {
				slog.Debug("RADIUS: Credentials cache miss reset",
					slog.String("username", miss.Username))
				delete(this.stateCache, key)
			}

			continue
		}

		sess, ok := entry.(*Session)
		if !ok {
			delete(this.stateCache, key)
			continue
		}

		if sess.Context.Err() != nil {

			wg.Add(1)

			slog.Debug("RADIUS: Session done",
				slog.String("sid", sess.ID.String()),
				slog.String("reason", sess.Context.Err().Error()))

			go func(sess *Session) {

				defer wg.Done()

				if err := this.acctStopSession(ctx, sess); err != nil {
					slog.Error("RADIUS: Failed to stop session accounting",
						slog.String("err", err.Error()),
						slog.String("sid", sess.ID.String()),
						slog.String("stop_reason", "cancelled"))
				}

			}(sess)

			delete(this.stateCache, key)
			continue
		}

		if sess.IdleTimeout > 0 && now.Sub(sess.LastActivity) > sess.IdleTimeout {

			sess.CancelContext()

			wg.Add(1)

			slog.Debug("RADIUS: Session cancelled by idle timeout",
				slog.String("sid", sess.ID.String()))

			go func(sess *Session) {

				defer wg.Done()

				sess.ContextWg.Wait()

				if err := this.acctStopSession(ctx, sess); err != nil {
					slog.Error("RADIUS: Error stopping session accounting",
						slog.String("err", err.Error()),
						slog.String("sid", sess.ID.String()),
						slog.String("stop_reason", "idle"))
				}

			}(sess)

			delete(this.stateCache, key)
			continue
		}

		if sess.LastActSync.Before(syncActivityAfter) {

			slog.Debug("RADIUS: Session accounting update",
				slog.String("sid", sess.ID.String()))

			wg.Add(1)

			go func(sess *Session) {

				defer wg.Done()

				if err := this.acctUpdateSession(ctx, sess); err != nil {
					slog.Error("RADIUS: Failed to update session accounting",
						slog.String("err", err.Error()),
						slog.String("sid", sess.ID.String()))
				}

			}(sess)

			sess.LastActSync = now
		}
	}
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
	if sessID.Valid {
		slog.Error("RADIUS DAC: DM doesn't contain a valid session id",
			slog.String("ip", req.RemoteAddr.(*net.UDPAddr).IP.String()))
		return
	}

	sess := this.lookupCachedSessionByID(sessID.UUID)
	if sess == nil {

		slog.Warn("RADIUS DAC: DM session ID not found",
			slog.String("sid", sessID.UUID.String()),
			slog.String("dac_addr", req.RemoteAddr.String()))

		resp := req.Response(radius.CodeDisconnectNAK)
		rfc3576.ErrorCause_Set(resp, rfc3576.ErrorCause_Value_SessionContextNotFound)
		wrt.Write(resp)

		return
	}

	if sess.Context.Err() == nil {
		sess.CancelContext()
	}

	slog.Info("RADIUS DAC: DM OK",
		slog.String("sid", sess.ID.String()),
		slog.String("dac_addr", req.RemoteAddr.String()))

	wrt.Write(req.Response(radius.CodeDisconnectACK))
}

func (this *radiusController) dacHandleCOA(wrt radius.ResponseWriter, req *radius.Request) {

	sessID := SessionIdFromBytes(rfc2866.AcctSessionID_Get(req.Packet))
	if sessID.Valid {
		slog.Error("RADIUS DAC: CoA message doesn't contain a valid session id",
			slog.String("dac_addr", req.RemoteAddr.(*net.UDPAddr).IP.String()))
		return
	}

	sess := this.lookupCachedSessionByID(sessID.UUID)
	if sess == nil {

		slog.Warn("RADIUS DAC: CoA session ID not found",
			slog.String("sid", sessID.UUID.String()),
			slog.String("dac_addr", req.RemoteAddr.String()))

		wrt.Write(req.Response(radius.CodeCoANAK))
		resp := req.Response(radius.CodeCoANAK)
		rfc3576.ErrorCause_Set(resp, rfc3576.ErrorCause_Value_SessionContextNotFound)
		wrt.Write(resp)

		return
	}

	if idleTimeout := rfc2865.IdleTimeout_Get(req.Packet); idleTimeout > 0 {
		sess.IdleTimeout = time.Duration(idleTimeout) * time.Second
	} else {
		sess.IdleTimeout = 0
	}

	sess.MaxDataRateRx = int(rfc4679.MaximumDataRateDownstream_Get(req.Packet))
	sess.MaxDataRateTx = int(rfc4679.MaximumDataRateUpstream_Get(req.Packet))

	slog.Info("RADIUS DAC: CoA OK",
		slog.String("sid", sess.ID.String()),
		slog.Int("max_rx", sess.MaxDataRateRx),
		slog.Int("max_tx", sess.MaxDataRateTx),
		slog.Duration("idle_t", sess.IdleTimeout),
		slog.String("dac_addr", req.RemoteAddr.String()))

	wrt.Write(req.Response(radius.CodeCoAACK))
}
