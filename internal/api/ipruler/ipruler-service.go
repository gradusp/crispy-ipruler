package ipruler

import (
	"context"
	_ "embed"
	"encoding/json"
	"net"
	"net/url"
	"runtime"
	"sort"
	"sync"

	netPrivate "github.com/gradusp/crispy-ipruler/internal/pkg/net"
	"github.com/gradusp/crispy-ipruler/internal/pkg/netlink"
	"github.com/gradusp/crispy-ipruler/pkg/ipruler"
	"github.com/gradusp/go-platform/pkg/slice"
	"github.com/gradusp/go-platform/server"
	grpcRt "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

//NewIPRulerService creates inst of IP Ruler service
func NewIPRulerService(ctx context.Context) server.APIService {
	ret := &iprulerService{
		appCtx: ctx,
		sema:   make(chan struct{}, 1),
	}
	runtime.SetFinalizer(ret, func(o *iprulerService) {
		close(o.sema)
	})
	return ret
}

//GetSwaggerDocs get swagger spec docs
func GetSwaggerDocs() (*server.SwaggerSpec, error) {
	const api = "ip-ruler/GetSwaggerDocs"
	ret := new(server.SwaggerSpec)
	err := json.Unmarshal(rawSwagger, ret)
	return ret, errors.Wrap(err, api)
}

var (
	_ ipruler.IPRulerServiceServer = (*iprulerService)(nil)
	_ server.APIService            = (*iprulerService)(nil)
	_ server.APIGatewayProxy       = (*iprulerService)(nil)

	//go:embed ipruler.swagger.json
	rawSwagger []byte
)

const (
	family = 2
	mask32 = "/32"
)

type enumRulesConsumer = func(netlink.Rule) error

type iprulerService struct {
	ipruler.UnimplementedIPRulerServiceServer
	appCtx context.Context
	sema   chan struct{}
}

//Description impl server.APIService
func (srv *iprulerService) Description() grpc.ServiceDesc {
	return ipruler.IPRulerService_ServiceDesc
}

//RegisterGRPC impl server.APIService
func (srv *iprulerService) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	ipruler.RegisterIPRulerServiceServer(s, srv)
	return nil
}

//RegisterProxyGW impl server.APIGatewayProxy
func (srv *iprulerService) RegisterProxyGW(ctx context.Context, mux *grpcRt.ServeMux, c *grpc.ClientConn) error {
	return ipruler.RegisterIPRulerServiceHandler(ctx, mux, c)
}

func (srv *iprulerService) AddIPRule(ctx context.Context, req *ipruler.AddIPRuleRequest) (resp *emptypb.Empty, err error) {
	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	destIP := req.GetTunDestIP()
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("TunDestIP", destIP))

	var hcTunDestNetIP net.IP
	if hcTunDestNetIP, _, err = net.ParseCIDR(destIP + mask32); err != nil {
		err = errors.WithMessagef(err, "net.ParseCIDR(%s)", destIP+mask32)
		return
	}
	tableAndMark := netPrivate.IPType(hcTunDestNetIP).Int()
	span.SetAttributes(attribute.Int64("TableAndMark", tableAndMark))
	err = srv.enumRules(func(rule netlink.Rule) error {
		if int64(rule.Table) == tableAndMark && int64(rule.Mark) == tableAndMark {
			return status.Errorf(codes.AlreadyExists, "the rule with table '%v' always exists", tableAndMark)
		}
		return nil
	})
	if err != nil {
		return
	}
	rule := netlink.NewRule()
	rule.Mark = int(tableAndMark)
	rule.Table = int(tableAndMark)
	if err = netlink.RuleAdd(rule); err != nil {
		err = errors.WithMessagef(err, "netlink/RuleAdd table '%v'", tableAndMark)
	}
	if err == nil {
		resp = new(emptypb.Empty)
	}
	return resp, err
}

func (srv *iprulerService) RemoveIPRule(ctx context.Context, req *ipruler.RemoveIPRuleRequest) (resp *emptypb.Empty, err error) {
	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	destIP := req.GetTunDestIP()
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("TunDestIP", destIP))

	var hcTunDestNetIP net.IP
	if hcTunDestNetIP, _, err = net.ParseCIDR(destIP + mask32); err != nil {
		err = errors.WithMessagef(err, "net.ParseCIDR(%s)", destIP+mask32)
		return
	}
	tableAndMark := netPrivate.IPType(hcTunDestNetIP).Int()
	span.SetAttributes(attribute.Int64("TableAndMark", tableAndMark))
	success := errors.New("s")
	err = srv.enumRules(func(rule netlink.Rule) error {
		if !(int64(rule.Table) == tableAndMark && int64(rule.Mark) == tableAndMark) {
			return nil
		}
		if e := netlink.RuleDel(&rule); e != nil {
			return errors.WithMessagef(e, "netlink/RuleDel table '%v'", tableAndMark)
		}
		return success
	})
	if err == nil {
		err = status.Errorf(codes.NotFound, "no rule found for table '%v'", tableAndMark)
	} else if errors.Is(err, success) {
		resp = new(emptypb.Empty)
		err = nil
	}
	return resp, err
}

func (srv *iprulerService) GetState(ctx context.Context, _ *emptypb.Empty) (resp *ipruler.GetStateResponse, err error) {
	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	var rules netlink.Rules
	if rules, err = netlink.RuleList(family); err != nil {
		err = errors.WithMessage(err, "netlink/RuleList")
		return
	}
	resp = new(ipruler.GetStateResponse)
	for i := range rules {
		if r := rules[i]; r.Mark > 0 {
			resp.Fwmarks = append(resp.Fwmarks, int64(r.Mark))
		}
	}
	sort.Slice(resp.Fwmarks, func(i, j int) bool {
		return resp.Fwmarks[i] < resp.Fwmarks[j]
	})
	_ = slice.DedupSlice(&resp.Fwmarks, func(i, j int) bool {
		return resp.Fwmarks[i] == resp.Fwmarks[j]
	})
	return resp, nil
}

func (srv *iprulerService) enumRules(c enumRulesConsumer) error {
	list, err := netlink.RuleList(family)
	if err != nil {
		return errors.WithMessage(err, "netlink/RuleList")
	}
	for i := range list {
		if err = c(list[i]); err != nil {
			return err
		}
	}
	return nil
}

func (srv *iprulerService) correctError(err error) error {
	if err != nil && status.Code(err) == codes.Unknown {
		switch errors.Cause(err) {
		case context.DeadlineExceeded:
			return status.New(codes.DeadlineExceeded, err.Error()).Err()
		case context.Canceled:
			return status.New(codes.Canceled, err.Error()).Err()
		default:
			if e := new(url.Error); errors.As(err, &e) {
				switch errors.Cause(e.Err) {
				case context.Canceled:
					return status.New(codes.Canceled, err.Error()).Err()
				case context.DeadlineExceeded:
					return status.New(codes.DeadlineExceeded, err.Error()).Err()
				default:
					if e.Timeout() {
						return status.New(codes.DeadlineExceeded, err.Error()).Err()
					}
				}
			}
			err = status.New(codes.Internal, err.Error()).Err()
		}
	}
	return err
}

func (srv *iprulerService) enter(ctx context.Context) (leave func(), err error) {
	select {
	case <-srv.appCtx.Done():
		err = srv.appCtx.Err()
	case <-ctx.Done():
		err = ctx.Err()
	case srv.sema <- struct{}{}:
		var o sync.Once
		leave = func() {
			o.Do(func() {
				<-srv.sema
			})
		}
		return
	}
	err = status.FromContextError(err).Err()
	return
}
