package core

import (
	"context"
	"math"
	"net/netip"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Geo is a coarse, privacy-minimized location. | Geo 是粗略且最小化的地理位置。
type Geo struct {
	// Country is an ISO 3166-1 alpha-2 code. | Country 是 ISO 3166-1 alpha-2 国家代码。
	Country string `json:"country,omitempty"`
	// Region is an optional first-level administrative area. | Region 是可选的一级行政区。
	Region string `json:"region,omitempty"`
	// City is an optional city name. | City 是可选城市名。
	City string `json:"city,omitempty"`
	// Latitude is the latitude in degrees. | Latitude 是纬度（度）。
	Latitude float64 `json:"latitude,omitempty"`
	// Longitude is the longitude in degrees. | Longitude 是经度（度）。
	Longitude float64 `json:"longitude,omitempty"`
	// HasCoordinates reports whether latitude and longitude are meaningful. | HasCoordinates 报告经纬度是否有效。
	HasCoordinates bool `json:"has_coordinates,omitempty"`
}

// GeoResolver maps a client IP to a coarse location. | GeoResolver 把客户端 IP 映射到粗略位置。
//
// Implementations should return a zero Geo and a nil error when the address is
// unknown. Infrastructure errors are returned as errors and treated as a risk
// signal, not as an automatic block. | 地址未知时应返回零值 Geo 与 nil 错误。基础设施故障
// 应以错误返回，并作为风险信号处理，而不是自动拦截。
type GeoResolver interface {
	// Resolve returns the location of ip. | Resolve 返回 ip 的位置。
	Resolve(ctx context.Context, ip string) (Geo, error)
}

// GeoResolverFunc adapts a function to GeoResolver. | GeoResolverFunc 把函数适配为 GeoResolver。
type GeoResolverFunc func(ctx context.Context, ip string) (Geo, error)

// Resolve implements GeoResolver. | Resolve 实现 GeoResolver。
func (f GeoResolverFunc) Resolve(ctx context.Context, ip string) (Geo, error) {
	if f == nil {
		return Geo{}, errs.Detail(ErrInvalidOptions, "nil geo resolver function | 地理解析函数为 nil")
	}
	return f(ctx, ip)
}

// GeoEntry maps one CIDR prefix to a location. | GeoEntry 把一个 CIDR 前缀映射到位置。
type GeoEntry struct {
	// Prefix is the address range. | Prefix 是地址范围。
	Prefix netip.Prefix
	// Geo is the location assigned to the range. | Geo 是分配给该范围的位置。
	Geo Geo
}

// CIDRGeoResolver resolves IPs from a static prefix table. | CIDRGeoResolver 从静态前缀表解析 IP。
//
// The table is intended for private networks, office egress ranges and tests.
// Public geolocation normally comes from a host-supplied GeoResolver. | 该表适用于内网、
// 办公出口网段与测试。公网地理定位通常由宿主提供的 GeoResolver 完成。
type CIDRGeoResolver struct {
	entries []GeoEntry
}

// NewCIDRGeoResolver validates and copies a prefix table. | NewCIDRGeoResolver 校验并复制前缀表。
func NewCIDRGeoResolver(entries []GeoEntry) (*CIDRGeoResolver, error) {
	out := make([]GeoEntry, 0, len(entries))
	for i, entry := range entries {
		if !entry.Prefix.IsValid() {
			return nil, errs.Detail(ErrInvalidOptions, "geo entry %d has an invalid prefix | 地理条目 %d 的前缀无效", i, i)
		}
		entry.Prefix = entry.Prefix.Masked()
		entry.Geo = NormalizeGeo(entry.Geo)
		out = append(out, entry)
	}
	return &CIDRGeoResolver{entries: out}, nil
}

// Resolve implements GeoResolver with longest-prefix matching. | Resolve 以最长前缀匹配实现 GeoResolver。
func (r *CIDRGeoResolver) Resolve(ctx context.Context, ip string) (Geo, error) {
	if err := ctx.Err(); err != nil {
		return Geo{}, err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Geo{}, nil
	}
	best := -1
	var found Geo
	for _, entry := range r.entries {
		if !entry.Prefix.Contains(addr) {
			continue
		}
		if entry.Prefix.Bits() > best {
			best = entry.Prefix.Bits()
			found = entry.Geo
		}
	}
	return found, nil
}

// NormalizeGeo trims and upper-cases the country code. | NormalizeGeo 去空格并大写国家代码。
func NormalizeGeo(g Geo) Geo {
	g.Country = strings.ToUpper(strings.TrimSpace(g.Country))
	g.Region = strings.TrimSpace(g.Region)
	g.City = strings.TrimSpace(g.City)
	if g.Latitude < -90 || g.Latitude > 90 || g.Longitude < -180 || g.Longitude > 180 {
		g.HasCoordinates = false
	}
	return g
}

// SameCountry reports whether two locations agree on a known country. | SameCountry 报告两个位置是否在已知国家上一致。
func SameCountry(a, b Geo) bool {
	if a.Country == "" || b.Country == "" {
		return a.Country == "" && b.Country == ""
	}
	return strings.EqualFold(a.Country, b.Country)
}

// DistanceKM returns the great-circle distance between two coordinates. | DistanceKM 返回两个坐标之间的大圆距离。
func DistanceKM(a, b Geo) float64 {
	if !a.HasCoordinates || !b.HasCoordinates {
		return 0
	}
	const earthRadiusKM = 6371.0088
	lat1 := a.Latitude * math.Pi / 180
	lat2 := b.Latitude * math.Pi / 180
	dLat := (b.Latitude - a.Latitude) * math.Pi / 180
	dLon := (b.Longitude - a.Longitude) * math.Pi / 180
	h := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusKM * math.Asin(math.Sqrt(math.Min(1, h)))
}
