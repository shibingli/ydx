package challenge

import "github.com/shibingli/ydx/captcha/core"

// Core type aliases keep provider code focused on rendering. | Core 类型别名让生成器代码专注于渲染。
type (
	Point           = core.Point
	Type            = core.Type
	GenerateRequest = core.GenerateRequest
	Generated       = core.Generated
	Record          = core.Record
	Answer          = core.Answer
	CheckResult     = core.CheckResult
	Prompt          = core.Prompt
	ImageData       = core.ImageData
	Track           = core.Track
	TrackPoint      = core.TrackPoint
	Provider        = core.Provider
)

// Core challenge and error aliases. | Core 挑战与错误别名。
const (
	TypeText      = core.TypeText
	TypeClickText = core.TypeClickText
	TypeClickIcon = core.TypeClickIcon
	TypeSlide     = core.TypeSlide
	TypeScratch   = core.TypeScratch
	TypeSemantic  = core.TypeSemantic
	TypeRotate    = core.TypeRotate
)

var (
	ErrProvider = core.ErrProvider
	ErrAssets   = core.ErrAssets
)
