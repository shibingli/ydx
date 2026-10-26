package risk

import "github.com/shibingli/ydx/captcha/core"

// Core interaction aliases. | Core 交互类型别名。
type (
	Track      = core.Track
	TrackPoint = core.TrackPoint
	Point      = core.Point
	Signal     = core.Signals
)

// clampScore limits a score to 0-100. | clampScore 把分数限制在 0-100。
func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
