package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"

	radius "github.com/maddsua/layeh-radius"
	"github.com/maddsua/layeh-radius/rfc2866"
	"github.com/maddsua/layeh-radius/rfc4679"
)

type CliFlags struct {
	Cmd      *string
	Host     *string
	Secret   *string
	Sid      *string
	DataRate *int
}

func main() {

	cli := CliFlags{
		Cmd:      flag.String("cmd", "", "radius commmand to run {dm|coa}"),
		Host:     flag.String("host", "localhost:3799", "vx host addr {ip|addr|hostname}"),
		Secret:   flag.String("secret", os.Getenv("RADIUS_SECRET"), "radius protocol secret {string secret}"),
		Sid:      flag.String("sid", "", "provide session id to manage {uuid}"),
		DataRate: flag.Int("datarate", 0, "max connection rate {data_rate_bytes}"),
	}
	flag.Parse()

	switch *cli.Cmd {

	case "dm":

		if *cli.Sid == "" {
			slog.Error("Session ID required",
				slog.String("flag", "-sid=uuid"))
			os.Exit(1)
		}

		if err := sendDisconnect(*cli.Host, *cli.Secret, *cli.Sid); err != nil {
			slog.Error("Disconnect request failed",
				slog.String("err", err.Error()))
			os.Exit(1)
		}

	case "coa":

		if *cli.Sid == "" {
			slog.Error("Session ID required",
				slog.String("flag", "-sid=uuid"))
			os.Exit(1)
		}

		if err := sendCoa(*cli.Host, *cli.Secret, *cli.Sid, *cli.DataRate); err != nil {
			slog.Error("CoA request failed",
				slog.String("err", err.Error()))
			os.Exit(1)
		}
	default:
		slog.Error("Unknown command. Available commands are: 'coa', 'dm'")
		os.Exit(1)
	}
}

func sendDisconnect(host string, secret string, sid string) error {

	req := radius.New(radius.CodeDisconnectRequest, []byte(secret))

	rfc2866.AcctSessionID_Set(req, []byte(sid))

	resp, err := radius.Exchange(context.Background(), req, host)
	if err != nil {
		return err
	}

	if resp.Code != radius.CodeDisconnectACK {
		return errors.New(req.Code.String())
	}

	return err
}

func sendCoa(host string, secret string, sid string, maxRate int) error {

	req := radius.New(radius.CodeCoARequest, []byte(secret))

	rfc2866.AcctSessionID_Set(req, []byte(sid))

	rfc4679.ActualDataRateDownstream_Set(req, rfc4679.ActualDataRateDownstream(maxRate))
	rfc4679.ActualDataRateUpstream_Set(req, rfc4679.ActualDataRateUpstream(maxRate))

	resp, err := radius.Exchange(context.Background(), req, host)
	if err != nil {
		return err
	}

	if resp.Code != radius.CodeCoAACK {
		return errors.New(req.Code.String())
	}

	return err
}
