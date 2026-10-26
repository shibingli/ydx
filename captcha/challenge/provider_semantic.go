package challenge

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// semanticCategory is one promptable icon category. | semanticCategory 是一个可提示的图标分类。
type semanticCategory struct {
	// Name is the stable category identifier. | Name 是稳定分类标识。
	Name string
	// ZH is the Chinese prompt label. | ZH 是中文提示标签。
	ZH string
	// EN is the English prompt label. | EN 是英文提示标签。
	EN string
}

// semanticCategories is the semantic prompt vocabulary. | semanticCategories 是语义提示词表。
var semanticCategories = []semanticCategory{
	{Name: "fruit", ZH: "水果", EN: "fruit"},
	{Name: "animal", ZH: "动物", EN: "animals"},
	{Name: "vehicle", ZH: "交通工具", EN: "vehicles"},
	{Name: "nature", ZH: "自然景物", EN: "nature"},
	{Name: "object", ZH: "物品", EN: "objects"},
}

// semanticProvider renders category-selection challenges. | semanticProvider 渲染分类选择挑战。
type semanticProvider struct{}

// newSemanticProvider builds a semantic provider. | newSemanticProvider 构建语义点选生成器。
func newSemanticProvider() *semanticProvider { return &semanticProvider{} }

// Type implements Provider. | Type 实现 Provider。
func (p *semanticProvider) Type() Type { return TypeSemantic }

// Generate implements Provider. | Generate 实现 Provider。
func (p *semanticProvider) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := newRNG()
	if err != nil {
		return nil, err
	}
	category := semanticCategories[r.Intn(len(semanticCategories))]
	targetPool := iconsByCategory(category.Name)
	if len(targetPool) < 2 {
		return nil, errs.Detail(ErrProvider, "semantic category is too small | 语义分类过小")
	}
	targetCount := 2 + r.Intn(minInt(2, len(targetPool)-1))
	targets := pickIcons(r, targetPool, targetCount)
	chosen := make(map[string]struct{}, len(targets))
	for _, spec := range targets {
		chosen[spec.Name] = struct{}{}
	}
	distractors := make([]iconSpec, 0, len(iconCatalog))
	for _, spec := range iconCatalog {
		if spec.Category == category.Name {
			continue
		}
		if _, ok := chosen[spec.Name]; ok {
			continue
		}
		distractors = append(distractors, spec)
	}
	r.src.Shuffle(len(distractors), func(i, j int) { distractors[i], distractors[j] = distractors[j], distractors[i] })
	need := 6 - len(targets)
	if need > len(distractors) {
		need = len(distractors)
	}
	icons := append(append([]iconSpec(nil), targets...), distractors[:need]...)
	r.src.Shuffle(len(icons), func(i, j int) { icons[i], icons[j] = icons[j], icons[i] })
	c := newCanvas(req.Width, req.Height, r)
	c.background()
	cols, rows := 3, 2
	centers := cellCenters(r, cols, rows, req.Width, req.Height, 8)
	positions := make(map[string]Point, len(icons))
	tile := minInt(req.Width/cols, req.Height/rows) - 10
	if tile > 70 {
		tile = 70
	}
	for i, spec := range icons {
		center := centers[i%len(centers)]
		positions[spec.Name] = center
		drawIconTile(c, spec.Name, center.X, center.Y, tile)
	}
	targetPoints := make([]Point, 0, len(targets))
	labels := make([]string, 0, len(targets))
	for _, spec := range targets {
		targetPoints = append(targetPoints, positions[spec.Name])
		labels = append(labels, iconLabel(req, spec))
	}
	img, err := c.encodePNG("challenge")
	if err != nil {
		return nil, err
	}
	tolerance, err := clickTargetTolerance(targetPoints, 28)
	if err != nil {
		return nil, err
	}
	answer, err := encodeAnswer(clickState{Points: targetPoints, Labels: labels, Tolerance: tolerance, Ordered: false})
	if err != nil {
		return nil, err
	}
	categoryLabel := category.EN
	if isHanLocale(req.Locale) {
		categoryLabel = category.ZH
	}
	if req.Translate != nil {
		if translated := req.Translate("category." + category.Name); translated != "" {
			categoryLabel = translated
		}
	}
	prompt := localizedPrompt(req, "prompt.semantic", "hint.semantic", "Select all "+categoryLabel, "Multiple selections are allowed", categoryLabel)
	prompt.Count = len(targets)
	return &Generated{Prompt: prompt, Images: []ImageData{img}, Answer: answer}, nil
}

// Verify implements Provider. | Verify 实现 Provider。
func (p *semanticProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state clickState
	if err := decodeAnswer(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	behavior, reasons := scoreTrack(ans.Track, len(state.Points)+2)
	if len(ans.Points) != len(state.Points) {
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "semantic_count_mismatch")}, nil
	}
	used := make([]bool, len(state.Points))
	for _, point := range ans.Points {
		matched := false
		for i, target := range state.Points {
			if used[i] {
				continue
			}
			if distancePoint(point, target) <= float64(state.Tolerance) {
				used[i] = true
				matched = true
				break
			}
		}
		if !matched {
			return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "semantic_miss")}, nil
		}
	}
	for _, hit := range used {
		if !hit {
			return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "semantic_incomplete")}, nil
		}
	}
	return CheckResult{Passed: true, BehaviorScore: behavior, Reasons: reasons}, nil
}
