// Package risk scores client interaction and behavior signals.
// | Package risk 评估客户端交互与行为信号。
package risk

import (
	"math"
	"time"
)

// behaviorMaxPoints is the largest trajectory accepted from a client. | behaviorMaxPoints 是客户端轨迹的最大点数。
const behaviorMaxPoints = 512

// behaviorMaxMS is the longest accepted interaction duration. | behaviorMaxMS 是接受的最长交互时长。
const behaviorMaxMS = int64((5 * time.Minute) / time.Millisecond)

// scoreTrack scores a pointer trajectory for plausibility. | scoreTrack 评估指针轨迹的可信度。
//
// The result is a risk contribution, not a proof of humanity: a sophisticated
// bot can synthesize a convincing track, so the score is combined with policy,
// rate limits and optional proof of work. | 结果是风险贡献而非人类证明：高级机器人可以
// 合成可信轨迹，因此该分数与策略、限流及可选工作量证明组合使用。
func ScoreTrack(track Track, expectedPoints int) (int, []string) {
	score := 0
	var reasons []string
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}
	points := track.Points
	if len(points) == 0 {
		add(40, "track_missing")
		return clampScore(score), reasons
	}
	if len(points) > behaviorMaxPoints {
		add(10, "track_too_long")
		// Bound CPU and memory from direct API callers. | 限制直接调用 API 带来的 CPU 与内存开销。
		points = points[:behaviorMaxPoints]
	}
	if len(points) < 2 {
		add(30, "track_too_short")
	}
	start := track.StartedAt
	end := track.EndedAt
	if start == 0 {
		start = points[0].T
	}
	if end == 0 {
		end = points[len(points)-1].T
	}
	elapsed := end - start
	if elapsed <= 0 {
		add(30, "track_time_invalid")
	} else if elapsed > behaviorMaxMS {
		add(20, "track_too_slow")
	} else if elapsed < 80 {
		add(20, "track_too_fast")
	}
	lastT := int64(-1)
	lastX, lastY := 0, 0
	var path float64
	unique := make(map[Point]struct{}, len(points))
	monotonic := true
	for _, point := range points {
		if lastT >= 0 {
			if point.T < lastT {
				monotonic = false
			} else if point.T-lastT < 4 && len(points) > 8 {
				add(5, "track_timestamps_dense")
			}
			path += math.Hypot(float64(point.X-lastX), float64(point.Y-lastY))
		}
		lastT = point.T
		lastX, lastY = point.X, point.Y
		unique[Point{X: point.X, Y: point.Y}] = struct{}{}
	}
	if !monotonic {
		add(20, "track_time_reversed")
	}
	if len(unique) < 3 {
		add(20, "track_positions_static")
	}
	if path == 0 {
		add(30, "track_no_movement")
	} else if elapsed > 0 {
		speed := path / (float64(elapsed) / 1000)
		if speed > 5000 {
			add(20, "track_implausible_speed")
		}
	}
	if expectedPoints > 0 && len(points) < expectedPoints {
		add(10, "track_few_samples")
	}
	return clampScore(score), reasons
}

// trackDuration returns the client-reported duration. | trackDuration 返回客户端报告的时长。
func TrackDuration(track Track) time.Duration {
	start := track.StartedAt
	end := track.EndedAt
	if start == 0 && len(track.Points) > 0 {
		start = track.Points[0].T
	}
	if end == 0 && len(track.Points) > 0 {
		end = track.Points[len(track.Points)-1].T
	}
	if end <= start {
		return 0
	}
	return time.Duration(end-start) * time.Millisecond
}
