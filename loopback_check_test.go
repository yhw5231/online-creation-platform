package main

import "testing"

func TestRewriteLoopbackURL(t *testing.T) {
	cases := []struct{ name, in, base, want string }{
		{"loopback ip + http base", "http://127.0.0.1:8000/v1/media/images/img_x", "http://image2.vwo.ccwu.cc/", "http://image2.vwo.ccwu.cc/v1/media/images/img_x"},
		{"loopback host + https base", "http://localhost:8000/v1/media/a", "https://grok.7890456.xyz/v1", "https://grok.7890456.xyz/v1/media/a"},
		{"ipv6 loopback", "http://[::1]:8000/v1/media/a", "https://grok.7890456.xyz/v1", "https://grok.7890456.xyz/v1/media/a"},
		{"public url unchanged", "https://grok.7890456.xyz/v1/media/images/img_b", "http://image2.vwo.ccwu.cc/", "https://grok.7890456.xyz/v1/media/images/img_b"},
		{"data uri unchanged", "data:image/png;base64,AAAA", "https://grok.7890456.xyz/v1", "data:image/png;base64,AAAA"},
		{"relative path unchanged", "/images/x.jpg", "https://grok.7890456.xyz/v1", "/images/x.jpg"},
		{"base itself loopback unchanged", "http://127.0.0.1:8000/a", "http://127.0.0.1:8000", "http://127.0.0.1:8000/a"},
		{"private lan ip unchanged", "http://192.168.1.5:8000/a", "https://grok.7890456.xyz/v1", "http://192.168.1.5:8000/a"},
	}
	for _, c := range cases {
		if got := rewriteLoopbackURL(c.in, c.base); got != c.want {
			t.Errorf("%s: rewriteLoopbackURL(%q, %q) = %q, want %q", c.name, c.in, c.base, got, c.want)
		}
	}
}