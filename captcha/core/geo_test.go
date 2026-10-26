package core

import (
	"context"
	"net/netip"
	"testing"
)

func TestCIDRGeoResolverLongestPrefix(t *testing.T) {
	resolver, err := NewCIDRGeoResolver([]GeoEntry{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Geo: Geo{Country: "US"}},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Geo: Geo{Country: "CN"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	geo, err := resolver.Resolve(context.Background(), "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if geo.Country != "CN" {
		t.Fatalf("geo = %+v", geo)
	}
	if _, err := resolver.Resolve(context.Background(), "bad-ip"); err != nil {
		t.Fatal(err)
	}
}

func TestDistanceKM(t *testing.T) {
	a := Geo{Latitude: 31.23, Longitude: 121.47, HasCoordinates: true}
	b := Geo{Latitude: 39.90, Longitude: 116.40, HasCoordinates: true}
	d := DistanceKM(a, b)
	if d < 1000 || d > 1200 {
		t.Fatalf("Shanghai-Beijing distance = %f", d)
	}
}
