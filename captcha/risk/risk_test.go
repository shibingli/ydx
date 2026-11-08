package risk

import "testing"

func TestScoreTrackRejectsStaticAndTooFastTracks(t *testing.T) {
	static := Track{StartedAt: 0, EndedAt: 10, Points: []TrackPoint{{T: 0, X: 1, Y: 1}, {T: 5, X: 1, Y: 1}}}
	score, reasons := ScoreTrack(static, 3)
	if score < 40 || !containsReason(reasons, "track_positions_static") {
		t.Fatalf("static score=%d reasons=%v", score, reasons)
	}
	fast := Track{StartedAt: 0, EndedAt: 10, Points: []TrackPoint{{T: 0, X: 0, Y: 0}, {T: 1, X: 100, Y: 100}, {T: 2, X: 200, Y: 200}}}
	score, reasons = ScoreTrack(fast, 3)
	if score == 0 || !containsReason(reasons, "track_too_fast") {
		t.Fatalf("fast score=%d reasons=%v", score, reasons)
	}
}

func TestScoreTrackAcceptsHumanLikeTrack(t *testing.T) {
	score, reasons := ScoreTrack(goodTrack(), 3)
	if score != 0 {
		t.Fatalf("score=%d reasons=%v", score, reasons)
	}
}

// TestScoreTrackAcceptsHighFrequencyHumanTrack covers 500-1000 Hz pointing
// devices, which report sub-4ms timestamps but are still human input. |
// TestScoreTrackAcceptsHighFrequencyHumanTrack 覆盖 500-1000 Hz 指针设备：
// 其时间戳间隔小于 4ms，但仍属正常人类输入。
func TestScoreTrackAcceptsHighFrequencyHumanTrack(t *testing.T) {
	const count = 400
	points := make([]TrackPoint, 0, count)
	for i := 0; i < count; i++ {
		points = append(points, TrackPoint{T: int64(i * 2), X: 40 + i, Y: 80 + i%5, Kind: "move"})
	}
	track := Track{StartedAt: 0, EndedAt: int64((count - 1) * 2), Points: points}
	score, reasons := ScoreTrack(track, 8)
	if score != 5 {
		t.Fatalf("dense timestamp penalty must be bounded: score=%d reasons=%v", score, reasons)
	}
	dense := 0
	for _, reason := range reasons {
		if reason == "track_timestamps_dense" {
			dense++
		}
	}
	if dense != 1 {
		t.Fatalf("dense timestamp reason repeated %d times: %v", dense, reasons)
	}
}

func goodTrack() Track {
	points := make([]TrackPoint, 0, 12)
	for i := 0; i < 12; i++ {
		points = append(points, TrackPoint{T: int64(i * 30), X: 40 + i*5, Y: 80 + i*2, Kind: "move"})
	}
	return Track{StartedAt: 0, EndedAt: 330, Points: points}
}

func containsReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}
