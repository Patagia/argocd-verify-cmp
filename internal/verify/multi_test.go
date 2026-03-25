package verify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/Patagia/argocd-verify-cmp/internal/verify"
)

// stubVerifier is a Verifier that returns a preset error (nil = success).
type stubVerifier struct {
	err    error
	called int
}

func (s *stubVerifier) Verify(_ context.Context, _ name.Reference) error {
	s.called++
	return s.err
}

var testRef = func() name.Reference {
	ref, err := name.ParseReference("registry.example.com/app:v1.0.0")
	if err != nil {
		panic(err)
	}
	return ref
}()

func TestMultiVerifier_SinglePass(t *testing.T) {
	v := &stubVerifier{}
	mv := verify.NewMultiVerifier(v)

	if err := mv.Verify(context.Background(), testRef); err != nil {
		t.Errorf("expected success, got: %v", err)
	}
	if v.called != 1 {
		t.Errorf("verifier called %d times, want 1", v.called)
	}
}

func TestMultiVerifier_SingleFail(t *testing.T) {
	v := &stubVerifier{err: errors.New("bad key")}
	mv := verify.NewMultiVerifier(v)

	if err := mv.Verify(context.Background(), testRef); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestMultiVerifier_FirstPassSkipsRest(t *testing.T) {
	first := &stubVerifier{}
	second := &stubVerifier{}
	mv := verify.NewMultiVerifier(first, second)

	if err := mv.Verify(context.Background(), testRef); err != nil {
		t.Errorf("expected success, got: %v", err)
	}
	if first.called != 1 {
		t.Errorf("first verifier called %d times, want 1", first.called)
	}
	if second.called != 0 {
		t.Errorf("second verifier called %d times, want 0 (should be skipped)", second.called)
	}
}

func TestMultiVerifier_FallsBackToSecond(t *testing.T) {
	first := &stubVerifier{err: errors.New("old key expired")}
	second := &stubVerifier{}
	mv := verify.NewMultiVerifier(first, second)

	if err := mv.Verify(context.Background(), testRef); err != nil {
		t.Errorf("expected success via second verifier, got: %v", err)
	}
	if first.called != 1 {
		t.Errorf("first verifier called %d times, want 1", first.called)
	}
	if second.called != 1 {
		t.Errorf("second verifier called %d times, want 1", second.called)
	}
}

func TestMultiVerifier_AllFail(t *testing.T) {
	errA := errors.New("key A failed")
	errB := errors.New("key B failed")
	mv := verify.NewMultiVerifier(
		&stubVerifier{err: errA},
		&stubVerifier{err: errB},
	)

	err := mv.Verify(context.Background(), testRef)
	if err == nil {
		t.Fatal("expected error when all verifiers fail, got nil")
	}
	if !errors.Is(err, errA) {
		t.Errorf("expected wrapped errA in result, err = %v", err)
	}
	if !errors.Is(err, errB) {
		t.Errorf("expected wrapped errB in result, err = %v", err)
	}
}

func TestMultiVerifier_TriesAllBeforeFailing(t *testing.T) {
	verifiers := []*stubVerifier{
		{err: errors.New("fail 1")},
		{err: errors.New("fail 2")},
		{err: errors.New("fail 3")},
	}
	mv := verify.NewMultiVerifier(verifiers[0], verifiers[1], verifiers[2])

	if err := mv.Verify(context.Background(), testRef); err == nil {
		t.Fatal("expected error, got nil")
	}
	for i, v := range verifiers {
		if v.called != 1 {
			t.Errorf("verifier[%d] called %d times, want 1", i, v.called)
		}
	}
}
