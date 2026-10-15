package scheduler

import (
	"context"
	"errors"
	"testing"
)

// BeforeEnroll runs ahead of every enrollment attempt, so the device is
// described (os version, hardware id) before the first enroll is sent rather
// than only after the first inventory collection, which follows enrollment.
func TestEnsureEnrolled_DescribesDeviceBeforeEnrolling(t *testing.T) {
	var order []string
	transport := &scriptedEnroll{
		answer: func(int) error {
			order = append(order, "enroll")
			return errors.New("refused")
		},
		called: make(chan int, 1),
	}
	d, _, _ := signInDeps(t, transport, nil)
	d.BeforeEnroll = func() { order = append(order, "describe") }

	if _, err := d.ensureEnrolled(context.Background()); err == nil {
		t.Fatal("expected the scripted refusal")
	}
	if len(order) != 2 || order[0] != "describe" || order[1] != "enroll" {
		t.Fatalf("order = %v, want [describe enroll]", order)
	}
}

// Without BeforeEnroll the enrollment is attempted as before.
func TestEnsureEnrolled_BeforeEnrollIsOptional(t *testing.T) {
	transport := &scriptedEnroll{answer: func(int) error { return errors.New("refused") }, called: make(chan int, 1)}
	d, _, _ := signInDeps(t, transport, nil)
	if _, err := d.ensureEnrolled(context.Background()); err == nil {
		t.Fatal("expected the scripted refusal")
	}
	if transport.calls != 1 {
		t.Fatalf("enroll calls = %d, want 1", transport.calls)
	}
}
