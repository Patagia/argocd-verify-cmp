package verify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Patagia/argocd-verify-cmp/internal/verify"
)

func TestAllVerifier_AllPass(t *testing.T) {
	av := verify.NewAllVerifier(&stubVerifier{}, &stubVerifier{})
	if err := av.Verify(context.Background(), testRef); err != nil {
		t.Errorf("expected success, got: %v", err)
	}
}

func TestAllVerifier_FirstFails(t *testing.T) {
	errA := errors.New("first failed")
	av := verify.NewAllVerifier(&stubVerifier{err: errA}, &stubVerifier{})
	err := av.Verify(context.Background(), testRef)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errA) {
		t.Errorf("expected wrapped errA, got: %v", err)
	}
}

func TestAllVerifier_SecondFails(t *testing.T) {
	errB := errors.New("second failed")
	av := verify.NewAllVerifier(&stubVerifier{}, &stubVerifier{err: errB})
	err := av.Verify(context.Background(), testRef)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errB) {
		t.Errorf("expected wrapped errB, got: %v", err)
	}
}

func TestAllVerifier_AllFail(t *testing.T) {
	errA := errors.New("verifier A failed")
	errB := errors.New("verifier B failed")
	av := verify.NewAllVerifier(&stubVerifier{err: errA}, &stubVerifier{err: errB})
	err := av.Verify(context.Background(), testRef)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errA) {
		t.Errorf("expected wrapped errA, got: %v", err)
	}
	if !errors.Is(err, errB) {
		t.Errorf("expected wrapped errB, got: %v", err)
	}
}

func TestAllVerifier_CallsAll(t *testing.T) {
	errA := errors.New("fail")
	a := &stubVerifier{err: errA}
	b := &stubVerifier{}
	av := verify.NewAllVerifier(a, b)
	_ = av.Verify(context.Background(), testRef)
	if a.called != 1 {
		t.Errorf("first verifier called %d times, want 1", a.called)
	}
	if b.called != 1 {
		t.Errorf("second verifier called %d times, want 1 (must not short-circuit)", b.called)
	}
}
