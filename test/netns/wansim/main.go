// Command wansim is a userspace WAN emulator for the test rig: a UDP relay
// applying rate limiting, propagation delay, a bounded bottleneck queue and
// random loss in both directions. It reproduces the CI netem profiles in
// environments whose kernels lack sch_netem (containers, minimal VMs).
//
// Usage:
//
//	wansim -wan listen=10.11.1.1:51820,target=10.10.0.2:51820,rate=50mbit,delay=20ms,queue=1000 \
//	       -wan listen=10.11.2.1:51820,target=10.10.0.2:51820,rate=30mbit,delay=60ms,queue=1000,loss=0.02
//
// Each -wan relays one client socket (the newest source wins, like a NAT).
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type wanSpec struct {
	listen  string
	target  string
	rateBps float64
	delay   time.Duration
	jitter  time.Duration
	queue   int
	loss    float64
}

type wanFlags []wanSpec

func (w *wanFlags) String() string { return fmt.Sprint(*w) }

func (w *wanFlags) Set(s string) error {
	spec := wanSpec{queue: 1000}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("bad wan option %q", kv)
		}
		var err error
		switch k {
		case "listen":
			spec.listen = v
		case "target":
			spec.target = v
		case "rate":
			spec.rateBps, err = parseRate(v)
		case "delay":
			spec.delay, err = time.ParseDuration(v)
		case "jitter":
			spec.jitter, err = time.ParseDuration(v)
		case "queue":
			spec.queue, err = strconv.Atoi(v)
		case "loss":
			spec.loss, err = strconv.ParseFloat(v, 64)
		default:
			return fmt.Errorf("unknown wan option %q", k)
		}
		if err != nil {
			return fmt.Errorf("wan option %q: %w", kv, err)
		}
	}
	if spec.listen == "" || spec.target == "" {
		return fmt.Errorf("wan needs listen= and target=")
	}
	*w = append(*w, spec)
	return nil
}

func parseRate(s string) (float64, error) {
	s = strings.ToLower(s)
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "gbit"):
		mult, s = 1e9, strings.TrimSuffix(s, "gbit")
	case strings.HasSuffix(s, "mbit"):
		mult, s = 1e6, strings.TrimSuffix(s, "mbit")
	case strings.HasSuffix(s, "kbit"):
		mult, s = 1e3, strings.TrimSuffix(s, "kbit")
	}
	v, err := strconv.ParseFloat(s, 64)
	return v * mult, err
}

type packet struct {
	buf       []byte
	deliverAt time.Time
}

// shaper emulates one direction of one WAN: bounded queue, serialization
// at the configured rate, then propagation delay.
type shaper struct {
	spec    wanSpec
	ch      chan packet
	send    func([]byte)
	lastDep time.Time
	rng     *rand.Rand
	drops   atomic.Uint64
}

func newShaper(spec wanSpec, send func([]byte)) *shaper {
	s := &shaper{spec: spec, ch: make(chan packet, spec.queue), send: send,
		rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
	go s.run()
	return s
}

func (s *shaper) offer(b []byte) {
	if s.spec.loss > 0 && s.rng.Float64() < s.spec.loss {
		return
	}
	now := time.Now()
	dep := now
	if s.spec.rateBps > 0 {
		tx := time.Duration(float64(len(b)+28) * 8 / s.spec.rateBps * float64(time.Second))
		if s.lastDep.After(now) {
			dep = s.lastDep.Add(tx)
		} else {
			dep = now.Add(tx)
		}
		s.lastDep = dep
	}
	deliver := dep.Add(s.spec.delay)
	if s.spec.jitter > 0 {
		deliver = deliver.Add(time.Duration(s.rng.Int63n(int64(s.spec.jitter))))
	}
	select {
	case s.ch <- packet{buf: append([]byte(nil), b...), deliverAt: deliver}:
	default:
		s.drops.Add(1) // bottleneck queue overflow, like netem's limit
	}
}

func (s *shaper) run() {
	for p := range s.ch {
		if d := time.Until(p.deliverAt); d > 0 {
			time.Sleep(d)
		}
		s.send(p.buf)
	}
}

func relay(spec wanSpec) error {
	laddr, err := net.ResolveUDPAddr("udp", spec.listen)
	if err != nil {
		return err
	}
	client, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp", spec.target)
	if err != nil {
		return err
	}
	server, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}

	var clientAddr atomic.Pointer[netip.AddrPort]

	up := newShaper(spec, func(b []byte) { server.Write(b) })
	down := newShaper(spec, func(b []byte) {
		if a := clientAddr.Load(); a != nil {
			client.WriteToUDPAddrPort(b, *a)
		}
	})

	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := client.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			clientAddr.Store(&src)
			up.offer(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			down.offer(buf[:n])
		}
	}()
	log.Printf("wan %s -> %s: rate=%.0fbps delay=%s queue=%d loss=%.3f",
		spec.listen, spec.target, spec.rateBps, spec.delay, spec.queue, spec.loss)
	return nil
}

func main() {
	var wans wanFlags
	flag.Var(&wans, "wan", "listen=IP:PORT,target=IP:PORT[,rate=50mbit][,delay=20ms][,jitter=5ms][,queue=1000][,loss=0.02]")
	flag.Parse()
	if len(wans) == 0 {
		fmt.Fprintln(os.Stderr, "at least one -wan is required")
		os.Exit(2)
	}
	for _, spec := range wans {
		if err := relay(spec); err != nil {
			log.Fatalf("wan %s: %v", spec.listen, err)
		}
	}
	select {}
}
