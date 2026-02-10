package sniffer

import "testing"

func TestFlowTracker_TopN(t *testing.T) {
	ft := NewFlowTracker(10)
	ft.Track("a")
	ft.Track("a")
	ft.Track("b")
	ft.Track("c")
	ft.Track("c")
	ft.Track("c")

	top := ft.TopN(2)
	if len(top) != 2 {
		t.Fatalf("expected 2, got %d", len(top))
	}
	if top[0].Flow != "c" || top[0].Count != 3 {
		t.Fatalf("unexpected top[0]=%v", top[0])
	}
	if top[1].Flow != "a" || top[1].Count != 2 {
		t.Fatalf("unexpected top[1]=%v", top[1])
	}
}
